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
 * @method newSignature
 * @param secondPassphrase
 *
 * @return {Object}
 */

var createAsset = function createAsset(secondPassphrase) {
  var _cryptoModule$getKeys = _crypto2.default.getKeys(secondPassphrase),
      publicKey = _cryptoModule$getKeys.publicKey;

  return { signature: { publicKey: publicKey } };
};

/**
 * @method registerSecondPassphrase
 * @param {Object} Object - Object
 * @param {String} Object.passphrase
 * @param {String} Object.secondPassphrase
 * @param {Number} Object.timeOffset
 *
 * @return {Object}
 */

/*
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
 * Signature module provides functions for creating second signature registration transactions.
 * @class signature
 */
var registerSecondPassphrase = function registerSecondPassphrase(_ref) {
  var passphrase = _ref.passphrase,
      secondPassphrase = _ref.secondPassphrase,
      timeOffset = _ref.timeOffset;

  var keys = _crypto2.default.getKeys(passphrase);

  var transaction = {
    type: 1,
    amount: '0',
    fee: _constants.SIGNATURE_FEE.toString(),
    recipientId: null,
    senderPublicKey: keys.publicKey,
    timestamp: (0, _utils.getTimeWithOffset)(timeOffset),
    asset: createAsset(secondPassphrase)
  };

  return (0, _utils.prepareTransaction)(transaction, passphrase, secondPassphrase);
};

exports.default = registerSecondPassphrase;