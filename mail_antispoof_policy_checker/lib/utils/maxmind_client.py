"""MaxMind GeoIP client wrapper - Object-oriented version"""

import os
import json
import glob
import tarfile
import datetime
import tempfile
import threading
import requests
import urllib.parse
from typing import Optional, Dict, Any, List, Tuple
from pytz import timezone
import geoip2.database


class InvalidLicenseKeyError(Exception):
    """Exception raised when MaxMind license key is invalid"""
    pass


class MaxMindClient:
    """
    Object-oriented wrapper for MaxMind GeoIP database access.
    Handles database updates and IP information lookups.
    """

    DOWNLOAD_URL = "https://download.maxmind.com/app/geoip_download"
    VALIDATION_URL = "https://secret-scanning.maxmind.com/secrets/validate-license-key"
    DB_LIST = {
        "GeoLite2-City": [1, 4],  # Tuesday, Friday
        "GeoLite2-ASN": [0, 1, 2, 3, 4, 5, 6],  # Everyday
        "GeoLite2-Country": [1, 4]  # Tuesday, Friday
    }
    # Shared by all instances: concurrent checks (async mode) must not download the same
    # database at the same time.
    _update_lock = threading.Lock()

    def __init__(self, license_key: str, db_path: str = "./utils/maxmind", timezone_str: str = "EST", validate_key: bool = True):
        """
        Initialize MaxMind client.

        Args:
            license_key: MaxMind license key for database downloads
            db_path: Path to store MaxMind databases
            timezone_str: Timezone string for update scheduling
            validate_key: Whether to validate the license key on initialization

        Raises:
            InvalidLicenseKeyError: If validate_key=True and license key is invalid
        """
        # Validate license key if requested
        if validate_key:
            is_valid, message = self.validate_license_key(license_key)
            if not is_valid:
                raise InvalidLicenseKeyError(message)

        self.license_key = license_key
        self.db_path = db_path
        self.db_dir = os.path.join(db_path, "db")
        self.status_file = os.path.join(db_path, "status.json")
        self.tz = timezone(timezone_str)
        self._databases: Optional[List[str]] = None

        self._prepare_folders()

    @staticmethod
    def validate_license_key(license_key: str) -> Tuple[bool, str]:
        """
        Validate a MaxMind license key using the MaxMind API.

        Documentation: https://dev.maxmind.com/license-key-validation-api/

        Args:
            license_key: MaxMind license key to validate

        Returns:
            Tuple of (is_valid, message)
            - is_valid: True if key is valid, False otherwise
            - message: Success message or error description
        """
        if not license_key:
            return False, "License key is empty"

        try:
            # The API requires application/x-www-form-urlencoded content type
            response = requests.post(
                MaxMindClient.VALIDATION_URL,
                data={'license_key': license_key},
                headers={'Content-Type': 'application/x-www-form-urlencoded'},
                timeout=10
            )

            # 204 No Content = valid key
            if response.status_code == 204:
                return True, "License key is valid"

            # 4xx or 5xx = invalid or error
            if response.status_code >= 400:
                try:
                    error_data = response.json()
                    error_code = error_data.get('code', 'UNKNOWN')
                    error_message = error_data.get('error', 'Unknown error')
                    return False, f"{error_code}: {error_message}"
                except:
                    return False, f"Invalid license key (HTTP {response.status_code})"

            # Unexpected status code
            return False, f"Unexpected response (HTTP {response.status_code})"

        except requests.exceptions.Timeout:
            return False, "Validation request timed out"
        except requests.exceptions.ConnectionError:
            return False, "Could not connect to MaxMind validation service"
        except Exception as e:
            return False, f"Validation error: {str(e)}"

    def _prepare_folders(self):
        """Create necessary folders and status file if they don't exist"""
        os.makedirs(self.db_dir, exist_ok=True)

        if not os.path.exists(self.status_file):
            status = {db_name: "1900-01-01T00:00:00Z" for db_name in self.DB_LIST}
            with open(self.status_file, "w", encoding="utf-8") as f:
                json.dump(status, f, indent=4)

    def _next_weekday(self, d: datetime.datetime, weekday: int) -> datetime.datetime:
        """Calculate the next occurrence of a specific weekday"""
        days_ahead = weekday - d.weekday()
        if days_ahead <= 0:
            days_ahead += 7
        return d + datetime.timedelta(days_ahead)

    def _download_database(self, db_name: str) -> bool:
        """Download and extract a MaxMind database. Returns True on success."""
        params = {
            "edition_id": db_name,
            "license_key": self.license_key,
            "suffix": "tar.gz"
        }

        url = f"{self.DOWNLOAD_URL}?{urllib.parse.urlencode(params)}"
        response = requests.get(url, stream=True, timeout=120)
        if response.status_code != 200:
            return False

        # Unique temp file next to the databases (never in the current directory)
        fd, tarball_path = tempfile.mkstemp(prefix=f"{db_name}_", suffix=".tar.gz", dir=self.db_path)
        try:
            with os.fdopen(fd, 'wb') as f:
                f.write(response.raw.read())

            with tarfile.open(tarball_path) as tar:
                tar.extractall(path=self.db_dir)
        except (tarfile.TarError, EOFError, OSError):
            return False
        finally:
            if os.path.exists(tarball_path):
                os.remove(tarball_path)
        return True

    def _update_status(self, db_name: str):
        """Update the last update timestamp for a database"""
        last_update = datetime.datetime.now(self.tz).strftime("%Y-%m-%dT%H:%M:%SZ")

        with open(self.status_file, "r") as f:
            status = json.load(f)

        status[db_name] = last_update

        with open(self.status_file, "w", encoding="utf-8") as f:
            json.dump(status, f, indent=4)

    def update_databases(self, force: bool = False):
        """
        Update MaxMind databases if needed.

        Args:
            force: Force update regardless of schedule
        """
        with open(self.status_file, "r") as f:
            status = json.load(f)

        for db_name, update_days in self.DB_LIST.items():
            if not force:
                last_update_str = status[db_name]
                last_update = self.tz.localize(
                    datetime.datetime.strptime(last_update_str, "%Y-%m-%dT%H:%M:%SZ")
                )

                next_updates = [self._next_weekday(last_update, day) for day in update_days]
                should_update = any(next_date < datetime.datetime.now(self.tz) for next_date in next_updates)

                if should_update and self._download_database(db_name):
                    self._update_status(db_name)
            elif self._download_database(db_name):
                self._update_status(db_name)

    def _get_latest_databases(self) -> List[str]:
        """Get paths to the latest database files (update check done once per instance)"""
        if self._databases is None:
            with self._update_lock:
                if self._databases is None:
                    self._databases = self._find_databases()
        return self._databases

    def _find_databases(self) -> List[str]:
        """Update the databases if due, then return the latest database files"""
        self.update_databases()

        all_mmdb = glob.glob(os.path.join(self.db_dir, "*/*.mmdb"))

        if not all_mmdb:
            self.update_databases(force=True)

        asn_dbs = glob.glob(os.path.join(self.db_dir, "GeoLite2-ASN_*/GeoLite2-ASN.mmdb"))
        city_dbs = glob.glob(os.path.join(self.db_dir, "GeoLite2-City_*/GeoLite2-City.mmdb"))
        country_dbs = glob.glob(os.path.join(self.db_dir, "GeoLite2-Country_*/GeoLite2-Country.mmdb"))

        latest_asn = max(asn_dbs, key=os.path.getctime) if asn_dbs else None
        latest_city = max(city_dbs, key=os.path.getctime) if city_dbs else None
        latest_country = max(country_dbs, key=os.path.getctime) if country_dbs else None

        return [db for db in [latest_asn, latest_city, latest_country] if db]

    def get_ip_information(self, ip_address: str) -> Dict[str, Any]:
        """
        Get geographic and organizational information for an IP address.

        Args:
            ip_address: IP address to lookup

        Returns:
            Dictionary with IP information including:
            - as_organization: Autonomous System organization name
            - country_name: Country name
            - country_iso_code: ISO country code
            - city_name: City name
            - postal_code: Postal code
            - network: Network CIDR
        """
        databases = self._get_latest_databases()

        if not databases:
            return {}

        result = {
            "as_organization": None,
            "country_name": None,
            "country_iso_code": None,
            "city_name": None,
            "postal_code": None,
            "network": None
        }

        # Get ASN information
        asn_db = next((db for db in databases if "ASN" in db), None)
        if asn_db:
            try:
                with geoip2.database.Reader(asn_db) as reader:
                    response = reader.asn(ip_address)
                    result["as_organization"] = response.autonomous_system_organization
            except Exception:
                pass

        # Get City information (includes country)
        city_db = next((db for db in databases if "City" in db), None)
        if city_db:
            try:
                with geoip2.database.Reader(city_db) as reader:
                    response = reader.city(ip_address)
                    result["country_name"] = response.country.name
                    result["country_iso_code"] = response.country.iso_code
                    result["city_name"] = response.city.name
                    result["postal_code"] = response.postal.code
                    result["network"] = str(response.traits.network) if response.traits.network else None
            except Exception:
                pass

        return result

    @classmethod
    def from_environment(cls, env_var: str = "MAXMIND_LICENSE_KEY", **kwargs) -> 'MaxMindClient':
        """
        Create a MaxMindClient instance using a license key from an environment variable.

        Args:
            env_var: Name of the environment variable containing the license key
            **kwargs: Additional arguments to pass to the constructor

        Returns:
            MaxMindClient instance

        Raises:
            ValueError: If the environment variable is not set
        """
        license_key = os.environ.get(env_var)
        if not license_key:
            raise ValueError(f"Environment variable '{env_var}' not set")
        return cls(license_key, **kwargs)
