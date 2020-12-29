from mailu import models
from mailu.ui import ui
from flask import request
from flask import current_app as app

import flask
import os
import socket
import uuid


db = models.db



@ui.route('/api/test', methods=['GET'])
def test():
    return flask.jsonify(
        status = 'success',
        data = None
    )

@ui.route('/api/test/post', methods=['POST'])
def testPost():
    req_data = request.get_json()
    return flask.jsonify(
        status = 'success',
        data = req_data
    )

@ui.route('/api/v1/domain', methods=['POST'])
def registerNewDomain():
    """ Create a domain
    """

    req_data = request.get_json()
    domain_name = req_data['domainName']
    max_users = req_data['maxUsers']
    max_aliases = req_data['maxAliases']
    max_quota_bytes = req_data['maxQuotaBytes']

    domain = models.Domain.query.get(domain_name)
    if not domain:
        domain = models.Domain(name=domain_name, max_users=max_users,
                               max_aliases=max_aliases, max_quota_bytes=max_quota_bytes)
        db.session.add(domain)
        db.session.commit()

        return flask.jsonify(
            status='success',
            message='Domain added successfully',
            data=domain.id
        )

    else:
        return flask.jsonify(
            status='error',
            message='Domain already exists'
        )


@ui.route('/api/domain/limits', methods=['PUT'])
def setDomainLimits():
    """ Set domain limits
    """

    req_data = request.get_json()
    domain_name = req_data['domainName']
    max_users = req_data['maxUsers']
    max_aliases = req_data['maxAliases']
    max_quota_bytes = req_data['maxQuotaBytes']

    domain = models.Domain.query.get(domain_name)

    if domain:
        domain.max_users = max_users
        domain.max_aliases = max_aliases
        domain.max_quota_bytes = max_quota_bytes
        db.session.add(domain)
        db.session.commit()

        return flask.jsonify(
            status='success',
            message='Domain limits updated'
        )
    else:
        return flask.jsonify(
            status='error',
            message='Domain doesn\'t exists'
        )



@ui.route('/api/domain/manager', methods=['PUT'])
def setManager():
    """ Make a user manager of a domain
    """

    req_data = request.get_json()
    domain_name = req_data['domainName']
    user_name = req_data['username']

    domain = models.Domain.query.get(domain_name)
    manageruser = models.User.query.get(user_name + '@' + domain_name)
    if manageruser:
        domain.managers.append(manageruser)
        db.session.add(domain)
        db.session.commit()
        return flask.jsonify(
            status='success',
            message='User successfully has been set as manager of ' + domain_name
        )
    else:
        return flask.jsonify(
            status='error',
            message='User not found'
        )



@ui.route('/api/domain/<path:domain_name>', methods=['DELETE'])
def deleteDomain(domain_name):
    """delete domain_name"""
    domain = models.Domain.query.get(domain_name)
    if domain:
        db.session.delete(domain)
        db.session.commit()
        return flask.jsonify(
            status='success',
            message='Domain deleted successfully'
        )
    else:
        return flask.jsonify(
            status='error',
            message='Domain doesn\'t exists'
        )



@ui.route('/api/user', methods=['POST'])
def newUser():
    """ Create a user
    """

    req_data = request.get_json()
    domain_name = req_data['domainName']
    hash_scheme = req_data['hashScheme']
    username = req_data['username']
    password = req_data['password']
    displayed_name = req_data['displayedName']
    quota_bytes = req_data['quotaBytes']

    if hash_scheme is None:
        hash_scheme = app.config['PASSWORD_SCHEME']
    domain = models.Domain.query.get(domain_name)
    if not domain:
        return flask.jsonify(
            status='error',
            message='Domain doesn\'t exists'
        )

    user = models.User.query.get(username + "@" + domain_name )
    if not user:
        user = models.User(
            localpart=username,
            domain=domain,
            global_admin=False,
            displayed_name=displayed_name,
            quota_bytes=quota_bytes
        )
        user.set_password(password, hash_scheme=hash_scheme)
        db.session.add(user)
        db.session.commit()

        return flask.jsonify(
            status='success',
            message='User created successfully'
        )
    else:
        return flask.jsonify(
            status='error',
            message='User already exists'
        )


@ui.route('/api/user/<path:user_email>', methods=['DELETE'])
def deleteUser(user_email):
    """delete user"""
    user = models.User.query.get(user_email)
    if user:
        db.session.delete(user)
        db.session.commit()
        return flask.jsonify(
            status='success',
            message='User deleted successfully'
        )
    else:
        return flask.jsonify(
            status='error',
            message='User doesn\'t exists'
        )


@ui.route('/api/user/password', methods=['PUT'])
def changePassword():
    """ Change the password of an user
    """

    req_data = request.get_json()
    domain_name = req_data['domainName']
    hash_scheme = req_data['hashScheme']
    username = req_data['username']
    password = req_data['password']

    email = '{0}@{1}'.format(username, domain_name)
    user   = models.User.query.get(email)
    if hash_scheme is None:
        hash_scheme = app.config['PASSWORD_SCHEME']

    if user:
        user.set_password(password, hash_scheme=hash_scheme)
        db.session.add(user)
        db.session.commit()
        return flask.jsonify(
            status='success',
            message='Password updated successfully'
        )
    else:
        return flask.jsonify(
            status='error',
            message='User not found'
        )
