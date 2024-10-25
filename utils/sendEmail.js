const nodemailer = require("nodemailer");
require("dotenv").config();

const sendEmail = async (email, username, otp) => {
  try {
    console.log("Starting send email");
    const transporter = nodemailer.createTransport({
      host: process.env.SENDGRID_SERVER,
      port: process.env.SENDGRID_PORTS,
      secure: false,
      auth: {
        user: process.env.SENDGRID_USERNAME,
        pass: process.env.SENDGRID_API_KEY,
      },
    });

    //This Message Will go On Email of the User
    const message = `<!DOCTYPE html>
                                        <html lang="en">
                                        <head>
                                            <meta charset="UTF-8">
                                            <meta name="viewport" content="width=device-width, initial-scale=1.0">
                                            <title>OTP Email</title>
                                        </head>
                                        <body style="margin: 0; padding: 0; font-family: Arial, sans-serif; background-color: #f4f4f4;">
                                            <div style="width: 100%; background-color: #f4f4f4; padding: 20px;">
                                                <div style="max-width: 600px; margin: auto; background-color: #ffffff; border-radius: 8px; box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);">
                                                    <div style="padding: 20px; text-align: center;">
                                                        <h1 style="color: #333333;">Hi, ${username}!.... Your OTP Code</h1>
                                                        <p style="font-size: 18px; color: #555555;">Your One-Time Password (OTP) is:</p>
                                                        <h2 style="font-size: 36px; color: #4CAF50; margin: 20px 0;">${otp}</h2>
                                                        <p style="font-size: 16px; color: #555555;">This OTP will expire in <strong>10 minutes</strong>.</p>
                                                        <p style="font-size: 14px; color: #777777;">If you did not request this OTP, please ignore this email.</p>
                                                    </div>
                                                    <div style="background-color: #f9f9f9; padding: 10px; text-align: center; border-top: 1px solid #eaeaea;">
                                                        <p style="font-size: 14px; color: #777777;">&copy; 2023 AlphaHarry. All Rights Reserved.</p>
                                                    </div>
                                                </div>
                                            </div>
                                        </body>
                        </html>`;
    const mailOptions = {
      from: process.env.SENDGRID_SENDER, // Sender address from environment variables.
      to: `${username} <${email}>`, // Recipient's name and email address.
      subject: "API Testing", // Subject line.
      html: message, // Plaintext body.
    };
    console.log("Sending Emails");
    const info = await transporter.sendMail(mailOptions);
    console.log("Email sent:", info.response);
  } catch (err) {
    console.error("Error sending email:", err.message);
    throw new Error("Email not sent to the user"); // You can throw this to handle it upstream
  }
};

module.exports = sendEmail;
