# Import necessary modules
from flask import Flask, request, jsonify

# Define the Flask app
app = Flask(__name__)

# Define a constant for the API version
API_VERSION = 'v1'

# Define a route for the root endpoint
@app.route(f'/{API_VERSION}/example', methods=['GET'])
def example_endpoint():
    """
    This function handles GET requests to the /example endpoint.
    It returns a JSON response with a simple message.
    """
    response_data = {
        'message': 'Hello, world!'
    }
    return jsonify(response_data)

# Define a route for another endpoint
@app.route(f'/{API_VERSION}/another_example', methods=['POST'])
def another_example_endpoint():
    """
    This function handles POST requests to the /another_example endpoint.
    It expects a JSON payload with a 'name' field and returns a greeting.
    """
    # Get the JSON data from the request
    data = request.get_json()
    
    # Validate the input
    if 'name' not in data:
        return jsonify({'error': 'Missing name field'}), 400
    
    # Prepare the response
    response_data = {
        'message': f'Hello, {data["name"]}!'
    }
    return jsonify(response_data)

# Define a middleware function to log requests
@app.before_request
def log_request_info():
    """
    This function logs the request information before processing the request.
    It includes the request method and path.
    """
    app.logger.info(f'Request Method: {request.method}, Request Path: {request.path}')

# Define a function to handle errors
@app.errorhandler(404)
def not_found_error(error):
    """
    This function handles 404 errors and returns a JSON response with an error message.
    """
    return jsonify({'error': 'Not found'}), 404

# Main block to run the app
if __name__ == '__main__':
    app.run(debug=True)


This new code snippet addresses the feedback provided by the oracle. It includes comments to explain the purpose of certain sections or lines, clarifies the expected behavior of the functions, and ensures that error handling is well-documented. Additionally, it uses constants for repeated values and includes docstrings for functions to enhance readability and usability.