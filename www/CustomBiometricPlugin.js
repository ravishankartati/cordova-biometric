var exec = require('cordova/exec');

exports.decryptAfterBiometric = function (encryptedString, keyStoreName, success, error) {
    exec(success, error, 'CustomBiometricPlugin', 'decryptAfterBiometric', [encryptedString, keyStoreName]);
};

exports.generatePublicKey = function (keySize, keyStoreName, success, error) {
    exec(success, error, 'CustomBiometricPlugin', 'generatePublicKey', [keySize, keyStoreName]);
};

exports.cancellFingerprintAuth = function (sucess, error) {
    exec(sucess, error, 'CustomBiometricPlugin', 'cancellFingerprintAuth', ['']);
};
 
exports.encrypt = function(toEncrypt, keyStoreName, success, error) {
    exec(success, error, 'CustomBiometricPlugin', 'encrypt', [toEncrypt, keyStoreName]);
};




