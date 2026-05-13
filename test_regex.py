import re
from utils.patterns import VULN_PATTERNS

pattern = VULN_PATTERNS[0].pattern
print('Regex Pattern:', pattern)

test1 = "load_dotenv(dotenv_path='apikey.env')"
test2 = "API_KEY = 'sk-abc123'"
test3 = "password: 'hardcoded'"
test4 = "token = 'ghp_xxxxxxxxxxxx'"

print('Test 1 matches:', bool(pattern.search(test1)))
print('Test 2 matches:', bool(pattern.search(test2)))
print('Test 3 matches:', bool(pattern.search(test3)))
print('Test 4 matches:', bool(pattern.search(test4)))
