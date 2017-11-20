'use strict';

Object.defineProperty(exports, "__esModule", {
	value: true
});

var _toConsumableArray2 = require('babel-runtime/helpers/toConsumableArray');

var _toConsumableArray3 = _interopRequireDefault(_toConsumableArray2);

var _crypto = require('../crypto');

var _crypto2 = _interopRequireDefault(_crypto);

var _constants = require('../constants');

var _utils = require('./utils');

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

/**
 * @method castVotes
 * @param {Object} Object - Object
 * @param {String} Object.passphrase
 * @param {Array<String>} Object.votes
 * @param {Array<String>} Object.unvotes
 * @param {String} Object.secondPassphrase
 * @param {Number} Object.timeOffset
 *
 * @return {Object}
 */

var castVotes = function castVotes(_ref) {
	var passphrase = _ref.passphrase,
	    _ref$votes = _ref.votes,
	    votes = _ref$votes === undefined ? [] : _ref$votes,
	    _ref$unvotes = _ref.unvotes,
	    unvotes = _ref$unvotes === undefined ? [] : _ref$unvotes,
	    secondPassphrase = _ref.secondPassphrase,
	    timeOffset = _ref.timeOffset;

	var keys = _crypto2.default.getKeys(passphrase);

	(0, _utils.validatePublicKeys)([].concat((0, _toConsumableArray3.default)(votes), (0, _toConsumableArray3.default)(unvotes)));

	var plusPrependedVotes = (0, _utils.prependPlusToPublicKeys)(votes);
	var minusPrependedUnvotes = (0, _utils.prependMinusToPublicKeys)(unvotes);

	var allVotes = [].concat((0, _toConsumableArray3.default)(plusPrependedVotes), (0, _toConsumableArray3.default)(minusPrependedUnvotes));

	var transaction = {
		type: 3,
		amount: '0',
		fee: _constants.VOTE_FEE.toString(),
		recipientId: _crypto2.default.getAddress(keys.publicKey),
		senderPublicKey: keys.publicKey,
		timestamp: (0, _utils.getTimeWithOffset)(timeOffset),
		asset: {
			votes: allVotes
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
/**
 * Vote module provides functions for creating vote transactions.
 * @class vote
 */
exports.default = castVotes;