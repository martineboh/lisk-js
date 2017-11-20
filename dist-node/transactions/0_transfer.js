'use strict';

Object.defineProperty(exports, "__esModule", {
	value: true
});

var _crypto = require('../crypto');

var _crypto2 = _interopRequireDefault(_crypto);

var _constants = require('../constants');

var _utils = require('./utils');

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

/**
 * @method transfer
 * @param {Object} Object - Object
 * @param {String} Object.recipientId
 * @param {String} Object.recipientPublicKey
 * @param {String} Object.amount
 * @param {String} Object.passphrase
 * @param {String} Object.secondPassphrase
 * @param {String} Object.data
 * @param {Number} Object.timeOffset
 *
 * @return {Object}
 */

var transfer = function transfer(_ref) {
	var recipientId = _ref.recipientId,
	    recipientPublicKey = _ref.recipientPublicKey,
	    amount = _ref.amount,
	    passphrase = _ref.passphrase,
	    secondPassphrase = _ref.secondPassphrase,
	    data = _ref.data,
	    timeOffset = _ref.timeOffset;

	var _getAddressAndPublicK = (0, _utils.getAddressAndPublicKeyFromRecipientData)({
		recipientId: recipientId,
		recipientPublicKey: recipientPublicKey
	}),
	    address = _getAddressAndPublicK.address,
	    publicKey = _getAddressAndPublicK.publicKey;

	var keys = _crypto2.default.getKeys(passphrase);
	var fee = data ? _constants.TRANSFER_FEE + _constants.DATA_FEE : _constants.TRANSFER_FEE;
	var transaction = {
		type: 0,
		amount: amount.toString(),
		fee: fee.toString(),
		recipientId: address,
		recipientPublicKey: publicKey,
		senderPublicKey: keys.publicKey,
		timestamp: (0, _utils.getTimeWithOffset)(timeOffset),
		asset: {}
	};

	if (data && data.length > 0) {
		if (data !== data.toString('utf8')) throw new Error('Invalid encoding in transaction data. Data must be utf-8 encoded.');
		transaction.asset.data = data;
	}

	return (0, _utils.prepareTransaction)(transaction, passphrase, secondPassphrase);
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
 * Transaction module provides functions for creating balance transfer transactions.
 * @class transaction
 */
exports.default = transfer;