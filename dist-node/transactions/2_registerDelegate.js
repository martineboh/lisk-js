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
 * @method registerDelegate
 * @param {Object} Object - Object
 * @param {String} Object.passphrase
 * @param {String} Object.username
 * @param {String} Object.secondPassphrase
 * @param {Number} Object.timeOffset
 *
 * @return {Object}
 */

var registerDelegate = function registerDelegate(_ref) {
  var passphrase = _ref.passphrase,
      username = _ref.username,
      secondPassphrase = _ref.secondPassphrase,
      timeOffset = _ref.timeOffset;

  var keys = _crypto2.default.getKeys(passphrase);

  var transaction = {
    type: 2,
    amount: '0',
    fee: _constants.DELEGATE_FEE.toString(),
    recipientId: null,
    senderPublicKey: keys.publicKey,
    timestamp: (0, _utils.getTimeWithOffset)(timeOffset),
    asset: {
      delegate: {
        username: username
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
 * Delegate module provides functions to create delegate registration transactions.
 * @class delegate
 */
exports.default = registerDelegate;