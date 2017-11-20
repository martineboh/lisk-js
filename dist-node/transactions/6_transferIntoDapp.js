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
 * @method transferIntoDapp
 * @param {Object} Object - Object
 * @param {String} Object.dappId
 * @param {String} Object.amount
 * @param {String} Object.passphrase
 * @param {String} Object.secondPassphrase
 * @param {Number} Object.timeOffset
 *
 * @return {Object}
 */

var transferIntoDapp = function transferIntoDapp(_ref) {
  var dappId = _ref.dappId,
      amount = _ref.amount,
      passphrase = _ref.passphrase,
      secondPassphrase = _ref.secondPassphrase,
      timeOffset = _ref.timeOffset;

  var keys = _crypto2.default.getKeys(passphrase);

  var transaction = {
    type: 6,
    amount: amount.toString(),
    fee: _constants.IN_TRANSFER_FEE.toString(),
    recipientId: null,
    senderPublicKey: keys.publicKey,
    timestamp: (0, _utils.getTimeWithOffset)(timeOffset),
    asset: {
      inTransfer: {
        dappId: dappId
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
/**
 * Transfer module provides functions for creating "in" transfer transactions (balance transfers to
 * an individual dapp account).
 * @class transfer
 */
exports.default = transferIntoDapp;