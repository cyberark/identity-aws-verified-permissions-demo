# a flask application that exposes a rest API with a route of /redirect and has a query parameter called code.
# It prints the code in a text box with a button to copy it to the clipboard.

import requests
from flask import Flask, jsonify, request

app = Flask(__name__)


# this is the redirect url to the local server to print the authorization code
@app.route('/callback')
def redirect():
    code = request.args.get('code')
    html = f"""<!DOCTYPE html><html><body>
<p>Click on the button to copy the text from the text field</p>.<p>Try to paste the text (e.g. ctrl+v) afterwards in a different window, to see the effect.</p>
<input type="text" value="{code}" id="codeInput" size="50">
<button onclick="myFunction()">Copy Code</button>
<script>
function myFunction() {{
  // Get the text field
  var copyText = document.getElementById("codeInput");

  // Select the text field
  copyText.select();
  copyText.setSelectionRange(0, 99999); // For mobile devices

  // Copy the text inside the text field
  navigator.clipboard.writeText(copyText.value);
 
}}
</script>
</body>
</html>
    """
    return html


# Run the application
if __name__ == '__main__':
    app.run()
