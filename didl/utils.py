from enum import Enum
from datetime import datetime
import json 

class CustomJSONEncoder(json.JSONEncoder):
    """Custom JSON encoder to handle Enum and datetime objects."""
    def default(self, obj):
        if isinstance(obj, Enum):
            return obj.value
        if isinstance(obj, datetime):
            return obj.isoformat()
        return json.JSONEncoder.default(self, obj)
