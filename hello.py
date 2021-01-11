from flask import Flask
from flask_mail import Mail, Message

app = Flask(__name__)
app.config.update(
    DEBUG=True,
    MAIL_SERVER='smtp.qq.com',
    MAIL_PROT=25,
    MAIL_USE_TLS=True,
    MAIL_USE_SSL=False,
    MAIL_USERNAME='776716686@qq.com',
    MAIL_PASSWORD='trkiygofrtcwbeef',
    MAIL_DEBUG=True
)
mail = Mail(app)


@app.route('/')
def index():
    msg = Message("test ", sender='776716686@qq.com', recipients=['2080192758@qq.com'])  # 改成你自己的邮箱,并且第一处必须与上面配置的相同。
    msg.body = "This is a first email"
    msg.html = 'HTML body'
    with app.app_context():
        mail.send(msg)
    print("Mail sent successful!")
    return "Mail sent successful!"


if __name__ == "__main__":
    app.run()