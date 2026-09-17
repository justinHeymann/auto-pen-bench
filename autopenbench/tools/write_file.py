from pydantic import BaseModel
from pydantic import Field
import os
import re

from dotenv import load_dotenv
load_dotenv()

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

        scripts_dir = os.path.abspath(SCRIPTS)
        filepath = os.path.join(scripts_dir, safe_name)
        # Ensure the resolved path is directly within SCRIPTS
        if os.path.dirname(filepath) != scripts_dir:
            return f"Error: Invalid filename '{self.file_name}'"

        try:
            with open(filepath, 'w') as file:
                file.write(self.content)
            output = f'File /root/scripts/{safe_name} correctly saved.'
        except Exception as e:
            output = f"Error writing file: {e}"

        return output
