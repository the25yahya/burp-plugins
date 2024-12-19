from burp import IBurpExtender, IHttpListener, IContextMenuFactory, IExtensionStateListener, ITab
from javax.swing import JMenuItem, JButton, JPanel, BoxLayout
from java.io import PrintWriter
from java.net import URL
import os
import time

class BurpExtender(IBurpExtender, IHttpListener, IContextMenuFactory, IExtensionStateListener):
    
    def __init__(self):
        self.is_logging = False

    def registerExtenderCallbacks(self, callbacks):
        # Set up the extension
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName("log_stream")
        
        # Output to Burp Suite's console
        self.stdout = PrintWriter(callbacks.getStdout(), True)
        self.stderr = PrintWriter(callbacks.getStderr(), True)
        
        # Register HTTP listener to capture requests and responses
        callbacks.registerHttpListener(self)
        
        # Register extension state listener for saving state on disable
        callbacks.registerExtensionStateListener(self)
        
        # Create and add the button to a custom tab
        self.create_custom_tab(callbacks)
        
        self.stdout.println("log_stream plugin loaded.")
    
    def create_custom_tab(self, callbacks):
        """Create and add a custom tab with a button to Burp Suite's UI"""
        # Create a panel with a button
        panel = JPanel()
        panel.setLayout(BoxLayout(panel, BoxLayout.Y_AXIS))
        
        button = JButton("Toggle Log Stream")
        button.addActionListener(self.toggle_logging)
        panel.add(button)

        # Create custom ITab to add the panel as a Burp Suite tab
        custom_tab = CustomTab(panel)
        
        # Add the custom tab
        callbacks.addSuiteTab(custom_tab)
        self.stdout.println("Custom tab added with button.")

    def toggle_logging(self, event):
        """Start or stop logging requests and responses"""
        self.is_logging = not self.is_logging
        if self.is_logging:
            self.stdout.println("Log stream started.")
        else:
            self.stdout.println("Log stream stopped.")
    
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        """Capture and save requests/responses when logging is enabled"""
        if self.is_logging:
            try:
                if messageIsRequest:
                    self.capture_request(messageInfo)
                else:
                    self.capture_response(messageInfo)
            except Exception as e:
                self.stderr.println("Error capturing message: {}".format(str(e)))

    def capture_request(self, messageInfo):
        """Capture and save the HTTP request"""
        request_info = self.helpers.analyzeRequest(messageInfo)
        request_body = messageInfo.getRequest()
        headers = request_info.getHeaders()
        
        path = self.extract_path(messageInfo)
        self.save_to_file("request", path, headers, request_body)
    
    def capture_response(self, messageInfo):
        """Capture and save the HTTP response"""
        response = messageInfo.getResponse()
        if not response:
            return
        
        response_info = self.helpers.analyzeResponse(response)
        headers = response_info.getHeaders()
        
        path = self.extract_path(messageInfo)
        self.save_to_file("response", path, headers, response)
    
    def extract_path(self, messageInfo):
        """Extract the path from the URL of the HTTP message using Java's URL class"""
        try:
            request_info = self.helpers.analyzeRequest(messageInfo)
            url = request_info.getUrl()
            java_url = URL(url.toString())  # Parse the URL using Java's URL class
            return java_url.getPath().strip("/")
        except Exception as e:
            self.stderr.println("Error extracting path: {}".format(str(e)))
            return "unknown_path"

    def save_to_file(self, msg_type, path, headers, body):
        """Save the request/response to a file"""
        try:
            # Define directory and file paths
            output_dir = os.path.join("burp_logs", path)
            if not os.path.exists(output_dir):
                os.makedirs(output_dir)
            
            filename = os.path.join(output_dir, "{}_{}.txt".format(msg_type, int(time.time() * 1000)))
            
            # Convert body to string (Python 3 byte handling)
            body_str = body.decode('utf-8', errors='ignore')  # Assuming UTF-8 encoding
            
            with open(filename, 'w') as f:
                f.write("\n".join(headers) + "\n\n")
                f.write(body_str)
            
            self.stdout.println("Saved {} to {}".format(msg_type, filename))
        except Exception as e:
            self.stderr.println("Error writing to file: {}".format(str(e)))

    def extensionUnloaded(self):
        """Handle when the extension is unloaded, e.g., to clean up"""
        self.stdout.println("log_stream plugin unloaded.")

class CustomTab(ITab):
    def __init__(self, panel):
        self.panel = panel

    def getTabCaption(self):
        return "Log Stream"  # Tab name

    def getUiComponent(self):
        return self.panel  # The Swing component (JPanel) you want to display in the tab
