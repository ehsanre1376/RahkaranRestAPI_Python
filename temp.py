import tempfile
import os

# Define the variables
x = "This is the first line"
y = "This is the second line"

# Create a temporary file with a specific name
temp_dir = tempfile.gettempdir()
file_name = os.path.join(temp_dir, "ehsanre.txt")

# Write to the temporary file
with open(file_name, "w") as f:
    f.write(x + "\n")
    f.write(y + "\n")

print(f"Temporary file created at {file_name}")

from datetime import datetime
import json
#current_date = datetime.now().date()
json_date = datetime.now().date().isoformat()

print(f"Today's date in JSON format: {json_date}")


from datetime import datetime

# Given date strings
date_str1 = "12-Mar-2024 14:43:46 GMT"
date_str2 = "2024-03-02T14:08:53.123456"

# Parse the dates
date_format1 = "%d-%b-%Y %H:%M:%S %Z"
date_format2 = "%Y-%m-%dT%H:%M:%S.%f"
date1 = datetime.strptime(date_str1, date_format1)
date2 = datetime.strptime(date_str2, date_format2)

# Compare the dates
if date1 < date2:
    print(f"{date_str1} is earlier than {date_str2}")
elif date1 > date2:
    print(f"{date_str1} is later than {date_str2}")
else:
    print(f"{date_str1} and {date_str2} are equal")

# Output will indicate the comparison result
