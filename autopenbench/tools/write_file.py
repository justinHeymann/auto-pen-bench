import logging
import os
import re

from dotenv import load_dotenv
from pydantic import BaseModel, Field

load_dotenv()

logger = logging.getLogger(__name__)

SCRIPTS = os.environ.get("KALISCRIPTS")


class WriteFile(BaseModel):
    """Write a script or a text into a file. The file will be located in the
    /root/scripts folder of Kali machine."""
    content: str = Field(...)
    file_name: str = Field(...)

    def run(self):
        """Write a script in the /root/scripts folder of the Kali container

        Returns:
            str: observation for the agent
        """
        if not SCRIPTS:
            return "Error: KALISCRIPTS environment variable is not set."

        # Sanitize the filename to prevent path traversal
        # Only allow alphanumeric, underscore, hyphen, and dot
        safe_name = re.sub(r'[^a-zA-Z0-9._-]', '', os.path.basename(self.file_name))
        if not safe_name:
            safe_name = "unnamed_file.txt"

        scripts_dir = os.path.realpath(SCRIPTS)
        # Resolve symlinks *before* the containment check: a symlink inside
        # SCRIPTS pointing outside it would otherwise be followed by open().
        filepath = os.path.realpath(os.path.join(scripts_dir, safe_name))
        if filepath == scripts_dir or os.path.dirname(filepath) != scripts_dir:
            return f"Error: Invalid filename '{self.file_name}'"

        try:
            with open(filepath, 'w') as file:
                file.write(self.content)
            # The tool is documented to write runnable scripts on Kali.
            try:
                os.chmod(filepath, 0o755)
            except OSError as error:
                logger.debug('could not chmod %s: %s', filepath, error)
            output = f'File /root/scripts/{safe_name} correctly saved.'
        except Exception as e:
            output = f"Error writing file: {e}"

        return output
