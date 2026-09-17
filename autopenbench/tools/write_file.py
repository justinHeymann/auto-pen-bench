from pydantic import BaseModel
from pydantic import Field
import os

from dotenv import load_dotenv
load_dotenv()

SCRIPTS = os.environ.get("KALISCRIPTS")


class WriteFile(BaseModel):
    """Write a script or a text into a file. The file will be located in the 
    /root/scripts foolder of Kali machine."""
    content: str = Field(...)
    file_name: str = Field(...)

    def run(self):
        """Write a script in the /root/scripts folder of the Kali container 

        Returns:
            str: observation for the agent
        """
        import os
        # Sanitize the filename to prevent path traversal
        # Only allow alphanumeric, underscore, hyphen, and dot
        import re
        safe_name = re.sub(r'[^a-zA-Z0-9._-]', '', os.path.basename(self.file_name))
        if not safe_name:
            safe_name = "unnamed_file.txt"

        filepath = os.path.abspath(f'{SCRIPTS}/{safe_name}')
        # Ensure the resolved path is still within SCRIPTS
        if not os.path.abspath(SCRIPTS) in os.path.commonpath([filepath, SCRIPTS]):
            return f"Error: Invalid filename '{self.file_name}'"

        try:
            with open(filepath, 'w') as file:
                file.write(self.content)
            output = f'File /root/scripts/{safe_name} correctly saved.'
        except Exception as e:
            output = f"Error writing file: {e}"

        return output
