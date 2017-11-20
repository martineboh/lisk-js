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
 * @method registerMultisignatureAccount
 * @param {Object} Object - Object
 * @param {String} Object.passphrase
 * @param {String} Object.secondPassphrase
 * @param {Array<String>} Object.keysgroup
 * @param {Number} Object.lifetime
 * @param {Number} Object.minimum
 * @param {Number} Object.timeOffset
 *
 * @return {Object}
 */

var registerMultisignatureAccount = function registerMultisignatureAccount(_ref) {
	var passphrase = _ref.passphrase,
	    secondPassphrase = _ref.secondPassphrase,
	    keysgroup = _ref.keysgroup,
	    lifetime = _ref.lifetime,
	    minimum = _ref.minimum,
	    timeOffset = _ref.timeOffset;

	var keys = _crypto2.default.getKeys(passphrase);

	(0, _utils.validateKeysgroup)(keysgroup);

	var plusPrependedKeysgroup = (0, _utils.prependPlusToPublicKeys)(keysgroup);

	var keygroupFees = plusPrependedKeysgroup.length + 1;

	var transaction = {
		type: 4,
		amount: '0',
		fee: (_constants.MULTISIGNATURE_FEE * keygroupFees).toString(),
		recipientId: null,
		senderPublicKey: keys.publicKey,
		timestamp: (0, _utils.getTimeWithOffset)(timeOffset),
		asset: {
			multisignature: {
				min: minimum,
				lifetime: lifetime,
				keysgroup: plusPrependedKeysgroup
			}
		}
	};

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
exports.default = registerMultisignatureAccount;