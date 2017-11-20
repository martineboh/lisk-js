'use strict';

Object.defineProperty(exports, "__esModule", {
	value: true
});
exports.decryptPassphraseWithPassword = exports.encryptPassphraseWithPassword = exports.decryptMessageWithPassphrase = exports.encryptMessageWithPassphrase = undefined;

var _crypto = require('crypto');

var _crypto2 = _interopRequireDefault(_crypto);

var _convert = require('./convert');

var _hash = require('./hash');

var _hash2 = _interopRequireDefault(_hash);

var _keys = require('./keys');

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

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
var encryptMessageWithPassphrase = exports.encryptMessageWithPassphrase = function encryptMessageWithPassphrase(message, passphrase, recipientPublicKey) {
	var _getPrivateAndPublicK = (0, _keys.getPrivateAndPublicKeyBytesFromPassphrase)(passphrase),
	    senderPrivateKeyBytes = _getPrivateAndPublicK.privateKey;

	var convertedPrivateKey = (0, _convert.convertPrivateKeyEd2Curve)(senderPrivateKeyBytes);
	var recipientPublicKeyBytes = (0, _convert.hexToBuffer)(recipientPublicKey);
	var convertedPublicKey = (0, _convert.convertPublicKeyEd2Curve)(recipientPublicKeyBytes);
	var messageInBytes = naclInstance.encode_utf8(message);

	var nonce = naclInstance.crypto_box_random_nonce();
	var cipherBytes = naclInstance.crypto_box(messageInBytes, nonce, convertedPublicKey, convertedPrivateKey);

	var nonceHex = (0, _convert.bufferToHex)(nonce);
	var encryptedMessage = (0, _convert.bufferToHex)(cipherBytes);

	return {
		nonce: nonceHex,
		encryptedMessage: encryptedMessage
	};
};

/**
 * @method decryptMessageWithPassphrase
 * @param cipherHex
 * @param nonce
 * @param passphrase
 * @param senderPublicKey
 *
 * @return {string}
 */

var decryptMessageWithPassphrase = exports.decryptMessageWithPassphrase = function decryptMessageWithPassphrase(cipherHex, nonce, passphrase, senderPublicKey) {
	var _getPrivateAndPublicK2 = (0, _keys.getPrivateAndPublicKeyBytesFromPassphrase)(passphrase),
	    recipientPrivateKeyBytes = _getPrivateAndPublicK2.privateKey;

	var convertedPrivateKey = (0, _convert.convertPrivateKeyEd2Curve)(recipientPrivateKeyBytes);
	var senderPublicKeyBytes = (0, _convert.hexToBuffer)(senderPublicKey);
	var convertedPublicKey = (0, _convert.convertPublicKeyEd2Curve)(senderPublicKeyBytes);
	var cipherBytes = (0, _convert.hexToBuffer)(cipherHex);
	var nonceBytes = (0, _convert.hexToBuffer)(nonce);

	try {
		var decoded = naclInstance.crypto_box_open(cipherBytes, nonceBytes, convertedPublicKey, convertedPrivateKey);
		return naclInstance.decode_utf8(decoded);
	} catch (error) {
		if (error.message.match(/nacl\.crypto_box_open expected 24-byte nonce but got length 1/)) {
			throw new Error('Expected 24-byte nonce but got length 1.');
		}
		throw new Error('Something went wrong during decryption. Is this the full encrypted message?');
	}
};

/**
 * @method encryptAES256GCMWithPassword
 * @param {String} plainText utf8 - any utf8 string
 * @param {String} password utf8 - the password used to encrypt the passphrase
 *
 * @return {Object} - { cipher: '...', iv: '...', tag: '...' }
 */

var encryptAES256GCMWithPassword = function encryptAES256GCMWithPassword(plainText, password) {
	var iv = _crypto2.default.randomBytes(16);
	var passwordHash = (0, _hash2.default)(password, 'utf8');
	var cipher = _crypto2.default.createCipheriv('aes-256-gcm', passwordHash, iv);
	var firstBlock = cipher.update(plainText, 'utf8');
	var encrypted = Buffer.concat([firstBlock, cipher.final()]);
	var tag = cipher.getAuthTag();

	return {
		cipher: encrypted.toString('hex'),
		iv: iv.toString('hex'),
		tag: tag.toString('hex')
	};
};

var getTagBuffer = function getTagBuffer(tag) {
	var tagBuffer = (0, _convert.hexToBuffer)(tag);
	if ((0, _convert.bufferToHex)(tagBuffer) !== tag) {
		throw new Error('Tag must be a hex string.');
	}
	if (tagBuffer.length !== 16) {
		throw new Error('Tag must be 16 bytes.');
	}
	return tagBuffer;
};

/**
 * @method decryptAES256GCMWithPassword
 * @param {Object} Object - Object with cipher, iv and tag as hex strings
 * @param {String} Object.cipher - hex string AES-256-GCM cipher
 * @param {String} Object.iv - hex string for the initialisation vector
 * @param {String} Object.tag - hex string for the tag
 * @param {String} password utf8 - the password used to encrypt the passphrase
 *
 * @return {String} utf8
 */

var decryptAES256GCMWithPassword = function decryptAES256GCMWithPassword(_ref, password) {
	var cipher = _ref.cipher,
	    iv = _ref.iv,
	    tag = _ref.tag;

	var tagBuffer = getTagBuffer(tag);
	var passwordHash = (0, _hash2.default)(password, 'utf8');
	var decipher = _crypto2.default.createDecipheriv('aes-256-gcm', passwordHash, (0, _convert.hexToBuffer)(iv));
	decipher.setAuthTag(tagBuffer);
	var firstBlock = decipher.update((0, _convert.hexToBuffer)(cipher));
	var decrypted = Buffer.concat([firstBlock, decipher.final()]);

	return decrypted.toString();
};

/**
 * @method encryptPassphraseWithPassword
 * @param {String} passphrase utf8 - twelve word secret passphrase
 * @param {String} password utf8 - the password used to encrypt the passphrase
 *
 * @return {Object} - { cipher: '...', iv: '...', tag: '...' }
 */

var encryptPassphraseWithPassword = exports.encryptPassphraseWithPassword = encryptAES256GCMWithPassword;

/**
 * @method decryptPassphraseWithPassword
 * @param {Object} Object - Object with cipher, iv and tag as hex strings
 * @param {String} Object.cipher - hex string AES-256-GCM cipher
 * @param {String} Object.iv - hex string for the initialisation vector
 * @param {String} Object.tag - hex string for the tag
 * @param {String} password utf8 - the password used to encrypt the passphrase
 *
 * @return {String}
 */

var decryptPassphraseWithPassword = exports.decryptPassphraseWithPassword = decryptAES256GCMWithPassword;