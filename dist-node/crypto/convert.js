'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.convertPrivateKeyEd2Curve = exports.convertPublicKeyEd2Curve = exports.getAddress = exports.getAddressFromPublicKey = exports.toAddress = exports.getFirstEightBytesReversed = exports.hexToBuffer = exports.bufferToHex = exports.bufferToBigNumberString = exports.bigNumberToBuffer = undefined;

var _browserifyBignum = require('browserify-bignum');

var _browserifyBignum2 = _interopRequireDefault(_browserifyBignum);

var _ed2curve = require('ed2curve');

var _ed2curve2 = _interopRequireDefault(_ed2curve);

var _hash = require('./hash');

var _hash2 = _interopRequireDefault(_hash);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

/**
 * @method bigNumberToBuffer
 * @param {Number} bignumber
 * @param {Number} size
 *
 * @return {Buffer}
 */

var bigNumberToBuffer = exports.bigNumberToBuffer = function bigNumberToBuffer(bignumber, size) {
  return (0, _browserifyBignum2.default)(bignumber).toBuffer({ size: size });
};

/**
 * @method bufferToBigNumberString
 * @param {Buffer} bigNumberBuffer
 *
 * @return {String}
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
var bufferToBigNumberString = exports.bufferToBigNumberString = function bufferToBigNumberString(bigNumberBuffer) {
  return _browserifyBignum2.default.fromBuffer(bigNumberBuffer).toString();
};

/**
 * @method bufferToHex
 * @param {Buffer}
 *
 * @return {String}
 */

var bufferToHex = exports.bufferToHex = function bufferToHex(buffer) {
  return naclInstance.to_hex(buffer);
};

/**
 * @method hexToBuffer
 * @param {String}
 *
 * @return {Buffer}
 */

var hexToBuffer = exports.hexToBuffer = function hexToBuffer(hex) {
  return Buffer.from(hex, 'hex');
};

/**
 * @method getFirstEightBytesReversed
 * @param {Buffer} publicKeyBytes
 *
 * @return {Buffer}
 */

var getFirstEightBytesReversed = exports.getFirstEightBytesReversed = function getFirstEightBytesReversed(publicKeyBytes) {
  return Buffer.from(publicKeyBytes).slice(0, 8).reverse();
};

/**
 * @method toAddress
 * @param {Buffer} buffer
 *
 * @return {String}
 */

var toAddress = exports.toAddress = function toAddress(buffer) {
  return bufferToBigNumberString(buffer) + 'L';
};

/**
 * @method getAddressFromPublicKey
 * @param {String} publicKey
 *
 * @return {String}
 */

var getAddressFromPublicKey = exports.getAddressFromPublicKey = function getAddressFromPublicKey(publicKey) {
  var publicKeyHash = (0, _hash2.default)(publicKey, 'hex');

  var publicKeyTransform = getFirstEightBytesReversed(publicKeyHash);
  var address = toAddress(publicKeyTransform);

  return address;
};

/**
 * @method getAddress
 * @param {String} publicKey
 *
 * @return {String}
 */

var getAddress = exports.getAddress = getAddressFromPublicKey;

/**
 * @method convertPublicKeyEd2Curve
 * @param {String} publicKey
 *
 * @return {Object}
 */

var convertPublicKeyEd2Curve = exports.convertPublicKeyEd2Curve = _ed2curve2.default.convertPublicKey;

/**
 * @method convertPrivateKeyEd2Curve
 * @param {String} privateKey
 *
 * @return {Object}
 */

var convertPrivateKeyEd2Curve = exports.convertPrivateKeyEd2Curve = _ed2curve2.default.convertSecretKey;