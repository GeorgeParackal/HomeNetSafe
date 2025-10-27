import os


# Store all constants and paths here
WEBSITE_DIRECTORY_PATH = os.path.abspath(os.path.join(__file__, os.path.pardir))
PROJECT_DIRECTORY_PATH = os.path.abspath(os.path.join(WEBSITE_DIRECTORY_PATH, os.path.pardir))

STATIC_PATH = os.path.join(WEBSITE_DIRECTORY_PATH, 'static')
SHAREPOINT_PATH = os.path.join(STATIC_PATH, 'sharepoint')
