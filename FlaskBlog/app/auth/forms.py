#-*-coding:utf-8-*-
from flask_wtf import Form
from wtforms import StringField,PasswordField,BooleanField,SubmitField
from wtforms.validators import DataRequired, Length, Email, Regexp, EqualTo, ValidationError
from ..models import User

class LoginForm(Form):
    email = StringField('邮箱',validators=[DataRequired(),Length(1,64),Email()])
    password = PasswordField('密码',validators=[DataRequired()])
    remember_me = BooleanField('保持登录状态')
    submit = SubmitField('登录')

class RegistrationForm(Form):
    email = StringField('邮箱', validators=[DataRequired(), Length(1, 64), Email()])
    username = StringField('用户名',validators=[DataRequired(),Length(1,64),
                                             Regexp('^[A-Za-z][A-Za-z0-9_.]*$',0,
                                                    '用户名为大写字母，小写字母，数字_.组成')])

    password = PasswordField('密码', validators=[DataRequired(),EqualTo('password2',message='密码必须一致')])
    password2 = PasswordField('再输入密码',validators=[DataRequired()])
    submit = SubmitField('注册')

    def validate_email(self,field):
        if User.query.filter_by(email = field.data).first():
            raise ValidationError("邮箱已经被注册")

    def validate_username(self,field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError("用户名已经被注册")