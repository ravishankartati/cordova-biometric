var exec = require('cordova/exec');

exports.decryptAfterBiometric = function (encryptedString, keyStoreName, success, error) {
    exec(success, error, 'CustomBiometricPlugin', 'decryptAfterBiometric', [encryptedString, keyStoreName]);
};

exports.generatePublicKey = function (keySize, keyStoreName, success, error) {
    exec(success, error, 'CustomBiometricPlugin', 'generatePublicKey', [keySize, keyStoreName]);
};

exports.cancelFingerprintAuth = function (sucess, error) {
    exec(sucess, error, 'CustomBiometricPlugin', 'generatePublicKey', ['']);
};
 
// exports.encrypt = function(stringToencrypt, success, error) {
//     exec(success, error, 'CustomBiometricPlugin', 'encrypt', [stringToencrypt]);
// };




