'use strict';

Object.defineProperty(exports, "__esModule", {
	value: true
});

var _typeof2 = require('babel-runtime/helpers/typeof');

var _typeof3 = _interopRequireDefault(_typeof2);

var _crypto = require('../crypto');

var _crypto2 = _interopRequireDefault(_crypto);

var _constants = require('../constants');

var _utils = require('./utils');

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

var isInt = function isInt(n) {
	return parseInt(n, 10) === n;
}; /*
    * Copyright © 2017 Lisk Foundation
    *
    * See the LICENSE file at the top-level directory of this distribution
    * for licensing information.
    *
    * Unless otherwise agreed in a custom licensing agreement with the Lisk Foundation,
    * no part of this software, including this file, may be copied, modified,
    * propagated, or distributed except according to the terms contained in the
    * LICENSE file.
    *
    * Removal or modification of this copyright notice is prohibited.
    *
    */
/**
 * Dapp module provides functions used to create dapp registration transactions.
 * @class dapp
 */


var validateOptions = function validateOptions(options) {
	if ((typeof options === 'undefined' ? 'undefined' : (0, _typeof3.default)(options)) !== 'object') {
		throw new Error('Options must be an object.');
	}
	var category = options.category,
	    name = options.name,
	    type = options.type,
	    link = options.link;


	if (!isInt(category)) {
		throw new Error('Dapp category must be an integer.');
	}
	if (typeof name !== 'string') {
		throw new Error('Dapp name must be a string.');
	}
	if (!isInt(type)) {
		throw new Error('Dapp type must be an integer.');
	}
	if (typeof link !== 'string') {
		throw new Error('Dapp link must be a string.');
	}
};

/**
 * @method createDapp
 * @param {Object} Object - Object
 * @param {String} Object.passphrase
 * @param {String} Object.secondPassphrase
 * @param {Object} Object.options
 * @param {Number} Objec.timeOffset
 *
 * @return {Object}
 */

var createDapp = function createDapp(_ref) {
	var passphrase = _ref.passphrase,
	    secondPassphrase = _ref.secondPassphrase,
	    options = _ref.options,
	    timeOffset = _ref.timeOffset;

	validateOptions(options);

	var keys = _crypto2.default.getKeys(passphrase);

	var transaction = {
		type: 5,
		amount: '0',
		fee: _constants.DAPP_FEE.toString(),
		recipientId: null,
		senderPublicKey: keys.publicKey,
		timestamp: (0, _utils.getTimeWithOffset)(timeOffset),
		asset: {
			dapp: {
				category: options.category,
				name: options.name,
				description: options.description,
				tags: options.tags,
				type: options.type,
				link: options.link,
				icon: options.icon
			}
		}
	};

	return (0, _utils.prepareTransaction)(transaction, passphrase, secondPassphrase);
};

exports.default = createDapp;