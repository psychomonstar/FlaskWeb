#!/usr/bin/env python
# -*-coding:utf-8-*-
import os
from app import create_app, db
from app.models import User, Role, Post, Follow
from flask_script import Manager, Shell
from flask_migrate import Migrate, MigrateCommand

# app = create_app(os.getenv('FLASK_CONFIG') or 'default')
app = create_app('default')

manager = Manager(app)
migrate = Migrate(app)


def make_shell_context():
    return dict(app=app, db=db, User=User, Role=Role, Post=Post, Follow=Follow)


manager.add_command("shell", Shell(make_context=make_shell_context))
manager.add_command("db", MigrateCommand)

if __name__ == '__main__':
    app.run()
    # manager.run()
