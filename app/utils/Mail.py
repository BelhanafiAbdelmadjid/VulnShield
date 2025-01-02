# from protonmail_api_client import ProtonMailAPIClient
from protonmail import ProtonMail
import os
from dotenv import load_dotenv


# Determine the environment
env = os.getenv('FLASK_ENV', 'development')

# Load the appropriate .env file
if env == 'production':
    load_dotenv('.env.production')
else:
    load_dotenv('.env.development')

remove_domain = lambda email: email.split('@')[0]

class Mailing :
    def __init__(self):
        protonmail_username = os.getenv('PROTONMAIL_USERNAME')
        protonmail_password = os.getenv('PROTONMAIL_PASSWORD')
        if not protonmail_username or not protonmail_password:
            raise ValueError("ProtonMail credentials are not set in environment variables.")
        # Initialize the ProtonMail API client
        self.client = ProtonMail()
        self.client.login(protonmail_username, protonmail_password)
    def send_email(self,to_email, template, subject):
        # Load your ProtonMail credentials from environment variables

        new_message = self.client.create_message(
            # recipients=["to1@proton.me", "to2@gmail.com"],
            recipients=to_email,
            subject=subject,
            body=template,  # html or just text
        )

        # Send the email
        try:
            sent_message = self.client.send_message(new_message)
            print(f"Email sent successfully to {to_email}")
        except Exception as e:
            print(f"Failed to send email: {e}")
    def welcome_email(self,to_email,subject="Welcome to EyeSpy"):
        # Define the welcome email subject and body
        body = f"""
        <html>
        <head>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    margin: 0;
                    padding: 0;
                    background-color: #f4f4f4;
                }}
                .container {{
                    max-width: 600px;
                    margin: 20px auto;
                    padding: 20px;
                    background-color: #ffffff;
                    border-radius: 8px;
                    box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
                }}
                h1 {{
                    color: #333333;
                }}
                p {{
                    color: #666666;
                    line-height: 1.6;
                }}
                .button {{
                    display: inline-block;
                    padding: 10px 20px;
                    background-color: #007bff;
                    color: #ffffff;
                    text-decoration: none;
                    border-radius: 4px;
                }}
                .footer {{
                    margin-top: 20px;
                    text-align: center;
                    color: #999999;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Welcome to EyeSpy, {remove_domain(to_email)}!</h1>
                <p>We're thrilled to have you join the EyeSpy community! Your journey with us is just beginning, and we're excited to help you get the most out of our platform.</p>

                <h2>Getting Started</h2>
                <p>To help you get started, here are a few tips and resources:</p>
                <ol>
                    <li><strong>Explore Our Features</strong>: Check out our <a href="#">Getting Started Guide</a> to learn about all the features and tools available to you.</li>
                    <li><strong>Customize Your Experience</strong>: Personalize your settings to make EyeSpy work best for you.</li>
                    <li><strong>Join the Community</strong>: Connect with other users in our <a href="#">Community Forum</a> to share tips, ask questions, and get support.</li>
                </ol>

                <h2>What to Expect</h2>
                <ul>
                    <li><strong>Regular Updates</strong>: We'll keep you informed about new features, updates, and tips to enhance your experience.</li>
                    <li><strong>Support</strong>: Our support team is always here to help. Feel free to reach out with any questions or issues you encounter.</li>
                    <li><strong>Exclusive Offers</strong>: As a valued member, you'll receive exclusive offers and early access to new features.</li>
                </ul>

                <h2>We'd Love to Hear from You</h2>
                <p>Your feedback is incredibly important to us. If you have any suggestions, questions, or just want to say hi, please don't hesitate to contact us at <a href="mailto:{os.getenv('PROTONMAIL_USERNAME')}">{os.getenv('PROTONMAIL_USERNAME')}</a>.</p>

                <p>Thank you for choosing EyeSpy. We can't wait to see what you'll achieve with us!</p>

                <p class="footer">Best regards,<br>EyeSpy Team</p>
            </div>
        </body>
        </html>
        """

        # Call the send_email function to send the welcome email
        self.send_email([to_email], body,subject)
    def unsubscribed_email(self,to_email,subject="We're Sorry to See You Go"):
        # Define the unsubscribed email subject and body
        body = f"""
        <html>
        <head>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    margin: 0;
                    padding: 0;
                    background-color: #f4f4f4;
                }}
                .container {{
                    max-width: 600px;
                    margin: 20px auto;
                    padding: 20px;
                    background-color: #ffffff;
                    border-radius: 8px;
                    box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
                }}
                h1 {{
                    color: #333333;
                }}
                p {{
                    color: #666666;
                    line-height: 1.6;
                }}
                .button {{
                    display: inline-block;
                    padding: 10px 20px;
                    background-color: #007bff;
                    color: #ffffff;
                    text-decoration: none;
                    border-radius: 4px;
                }}
                .footer {{
                    margin-top: 20px;
                    text-align: center;
                    color: #999999;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>We're Sorry to See You Go, {remove_domain(to_email)}!</h1>
                <p>We're sad to see you unsubscribe from EyeSpy. We hope you found value in our services and we'd love to have you back anytime.</p>

                <h2>Why We'd Love to Have You Back</h2>
                <p>Here are a few reasons why you might want to reconsider:</p>
                <ul>
                    <li><strong>Exclusive Content</strong>: We regularly update our platform with new features and exclusive content that you won't find anywhere else.</li>
                    <li><strong>Community Support</strong>: Our community is always here to help. Whether you have questions or just want to share your experiences, you'll find a supportive group of users.</li>
                    <li><strong>Personalized Experience</strong>: We offer a range of customization options to make EyeSpy work best for you. From personalized settings to tailored recommendations, we strive to provide a unique experience for every user.</li>
                </ul>

                <h2>We Value Your Feedback</h2>
                <p>Your feedback is incredibly important to us. If there's anything we can do to improve our services or if you have any suggestions, please let us know. We're always looking for ways to make EyeSpy better for our users.</p>

                <p>If you ever decide to come back, we'll be here waiting with open arms. Thank you for being a part of the EyeSpy community, and we hope to see you again soon!</p>

                <p class="footer">Best regards,<br>EyeSpy Team</p>
            </div>
        </body>
        </html>
        """

        # Call the send_email function to send the unsubscribed email
        self.send_email([to_email],  body,subject)
    def weekly_cve_email(self,to_email,sub_id, cve_list,subject = "Your Weekly CVE Update from EyeSpy"):
        # Define the weekly CVE email subject and body
        
        body = f"""
        <html>
        <head>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    margin: 0;
                    padding: 0;
                    background-color: #f4f4f4;
                }}
                .container {{
                    max-width: 600px;
                    margin: 20px auto;
                    padding: 20px;
                    background-color: #ffffff;
                    border-radius: 8px;
                    box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
                }}
                h1 {{
                    color: #333333;
                }}
                p {{
                    color: #666666;
                    line-height: 1.6;
                }}
                .button {{
                    display: inline-block;
                    padding: 10px 20px;
                    background-color: #007bff;
                    color: #ffffff;
                    text-decoration: none;
                    border-radius: 4px;
                }}
                .footer {{
                    margin-top: 20px;
                    text-align: center;
                    color: #999999;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Your Weekly CVE Update !</h1>
                <p>Here are the latest CVEs based on your subscription preferences:</p>
                <ul>
        """

        # Add each CVE to the email body
        for cve in cve_list:
            cve_id = cve['id']
            cve_description = cve['description']
            cve_link = f"https://yourwebsite.com/cve/{cve_id}"
            body += f"""
                    <li>
                        <strong>{cve_id}</strong>: {cve_description}
                        <a href="{cve_link}" class="button">View Details</a>
                    </li>
            """

        body += f"""
                </ul>
                <p>Thank you for being a part of the EyeSpy community. We hope you find these updates helpful!</p>
                <p class="footer">Best regards,<br>EyeSpy Team</p>
            </div>
        </body>
        </html>
        """

        # Call the send_email function to send the weekly CVE email
        self.send_email([to_email], body, subject)


# Example usage
if __name__ == "__main__":
    # to_email = ["belhanafiabdelmadjid@gmail.com"]
    # template = "This is a test email sent using ProtonMail API Client."
    # send_email(to_email, template)

    # unsubscribed_email("belhanafiabdelmadjid@gmail.com")
    cve_list = [
        {'id': 'CVE-2023-1234', 'description': 'Description of CVE-2023-1234'},
        {'id': 'CVE-2023-5678', 'description': 'Description of CVE-2023-5678'},
        {'id': 'CVE-2023-9101', 'description': 'Description of CVE-2023-9101'},
        {'id': 'CVE-2023-1112', 'description': 'Description of CVE-2023-1112'},
        {'id': 'CVE-2023-1314', 'description': 'Description of CVE-2023-1314'}
    ]

    weekly_cve_email(['belhanafiabdelmadjid@gmail.com','madjidlethug0@gmail.com'],5,cve_list)