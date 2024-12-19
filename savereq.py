from burp import IBurpExtender, IContextMenuFactory
from javax.swing import JMenuItem
from java.io import PrintWriter
import os
import time
import urlparse  # Python 2 module

class BurpExtender(IBurpExtender, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        # Set up the extension
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Save to Machine")
        
        # Output to Burp Suite's console
        self.stdout = PrintWriter(callbacks.getStdout(), True)
        self.stderr = PrintWriter(callbacks.getStderr(), True)
        
        # Register context menu factory
        callbacks.registerContextMenuFactory(self)
        
        self.stdout.println("Plugin loaded: Save to Machine")
    
    def createMenuItems(self, invocation):
        # Add a menu item to the context menu
        menu_item = JMenuItem("Save to Machine")
        menu_item.addActionListener(lambda event: self.save_request_response(invocation))
        return [menu_item]
    
    def save_request_response(self, invocation):
        try:
            # Get selected HTTP messages
            selected_messages = invocation.getSelectedMessages()
            
            if not selected_messages:
                self.stdout.println("No request/response selected.")
                return
            
            for message in selected_messages:
                # Save request and response
                path = self.extract_path(message)
                self.save_request(message, path)
                self.save_response(message, path)
            
            self.stdout.println("Selected requests/responses saved successfully.")
        except Exception as e:
            self.stderr.println("Error: {}".format(str(e)))

    def extract_path(self, messageInfo):
        # Extract the path from the request URL
        try:
            request_info = self.helpers.analyzeRequest(messageInfo)
            url = request_info.getUrl()
            parsed_url = urlparse.urlparse(url.toString())  # Using Python 2's urlparse
            return parsed_url.path.strip("/")
        except Exception as e:
            self.stderr.println("Error extracting path: {}".format(str(e)))
            return "unknown_path"

    def save_request(self, messageInfo, path):
        # Extract the request
        request_info = self.helpers.analyzeRequest(messageInfo)
        request_body = messageInfo.getRequest()
        headers = request_info.getHeaders()
        
        # Save to file
        self.save_to_file("request", path, headers, request_body)
    
    def save_response(self, messageInfo, path):
        try:
            # Extract the response
            response = messageInfo.getResponse()
            
            if not response:
                self.stdout.println("No response available for this request.")
                return
            
            response_info = self.helpers.analyzeResponse(response)
            headers = response_info.getHeaders()
            self.save_to_file("response", path, headers, response)
        except Exception as e:
            self.stderr.println("Error saving response: {}".format(str(e)))
    
    def save_to_file(self, msg_type, path, headers, body):
        try:
            # Define directory and file paths
            output_dir = os.path.join("burp_logs", path)
            if not os.path.exists(output_dir):
                os.makedirs(output_dir)
            
            filename = os.path.join(output_dir, "{}_{}.txt".format(msg_type, int(time.time() * 1000)))
            
            # Convert body to string
            body_str = ''.join(chr(b & 0xff) for b in body)  # Convert byte array to string
            
            with open(filename, 'w') as f:
                f.write("\n".join(headers) + "\n\n")
                f.write(body_str)
            
            self.stdout.println("Saved {} to {}".format(msg_type, filename))
        except Exception as e:
            self.stderr.println("Error writing to file: {}".format(str(e)))
