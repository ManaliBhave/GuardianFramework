import spacy
import requests
from bs4 import BeautifulSoup
import re

# Take the domain name as user input
domain_name = input("Enter the domain name (e.g., google.com): ")

# Construct the URL
url = f"https://hypestat.com/info/{domain_name}"

response = requests.get(url)

if response.status_code == 200:
    soup = BeautifulSoup(response.content, "html.parser")

    text_content = soup.get_text()

    file_name = "scraped_content.txt"

    with open(file_name, "w", encoding="utf-8") as file:
        file.write(text_content)
    
    print(f"Scraped content has been saved to '{file_name}'.")
else:
    print("Failed to retrieve the web page.")

nlp = spacy.load("en_core_web_md")

# Define a regular expression pattern to extract the number value after "daily unique visitors"
pattern = r"daily unique visitors:\s*([\d,]+)"

# Use regular expression to find matches in the text
matches = re.findall(pattern, text_content, re.IGNORECASE)

# Check if any matches were found
if matches:
    # Extract the number from the first match (you can iterate over matches if there are multiple)
    number_value = matches[0].replace(",", "")  # Remove commas if present
    print(f"Number of daily unique visitors: {number_value}")
else:
    print("No matches found for 'daily unique visitors'.")
 