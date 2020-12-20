from flask import jsonify

import flask

@app.route('/v1/domains', methods=['GET'])
def domain_list():
    return jsonify(
        status = 'success',
        data = None
    )