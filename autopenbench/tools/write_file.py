import logging
import os
import re

from dotenv import load_dotenv
from pydantic import BaseModel, Field

load_dotenv()

logger = logging.getLogger(__name__)


def scripts_dir():
    """The Kali scripts directory (bind-mounted as /root/scripts), if any.

    Read lazily, like the other harness settings, so a missing or changed
    ``KALISCRIPTS`` is reported by :meth:`WriteFile.run` instead of being
    frozen at import time.
    """
    return os.environ.get("KALISCRIPTS")


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
        scripts = scripts_dir()
        if not scripts:
            return "Error: KALISCRIPTS environment variable is not set."

        # Sanitize the filename to prevent path traversal
        # Only allow alphanumeric, underscore, hyphen, and dot
        safe_name = re.sub(r'[^a-zA-Z0-9._-]', '', os.path.basename(self.file_name))
        if not safe_name:
            safe_name = "unnamed_file.txt"

        scripts_path = os.path.realpath(scripts)
        # Resolve symlinks *before* the containment check: a symlink inside
        # the scripts directory pointing outside it would otherwise be
        # followed by open().
        filepath = os.path.realpath(os.path.join(scripts_path, safe_name))
        if filepath == scripts_path or os.path.dirname(filepath) != scripts_path:
            return f"Error: Invalid filename '{self.file_name}'"

        try:
            # The content comes from the model and may be any text, so the
            # encoding is pinned rather than left to the environment's locale.
            with open(filepath, 'w', encoding='utf-8') as file:
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
