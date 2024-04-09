/**
 * Route Mappings
 * (sails.config.routes)
 *
 * Your routes tell Sails what to do each time it receives a request.
 *
 * For more information on configuring custom routes, check out:
 * https://sailsjs.com/anatomy/config/routes-js
 */

module.exports.routes = {

  /***************************************************************************
  *                                                                          *
  * Make the view located at `views/homepage.ejs` your home page.            *
  *                                                                          *
  * (Alternatively, remove this and add an `index.html` file in your         *
  * `assets` directory)                                                      *
  *                                                                          *
  ***************************************************************************/

  '/': "FileController.LoginPage",
  "POST /EncryptForMe": "FileController.EncryptFile",
  "POST /EncryptForMePub": "FileController.EncryptFileWithPub",
  "POST /DecryptForMe": "FileController.DecryptFile",
  "GET /DecryptForMe2": "FileController.DecryptFile2",
  "POST /DecryptForMePub": "FileController.DecryptFileWithPub",
  "GET /publicKey": "FileController.importKey",
  "GET /test": "FileController.dispatch",
  "POST /file/uploadPubEn": "FileController.uploadPubEn",

  'POST /upload': {
    controller: 'FileController',
    action: 'upload'
  },
  "GET /Success": {
    view: 'Success'
  },
  
  "POST /SuccessDownload": "FileController.SuccessDownload",


  "POST /downloadwithPW":"FileController.downloadwithPW",

  'POST /download': "FileController.download",

  'POST /uploadwithPW': {
    controller: 'FileController',
    action: 'uploadwithPW'
  },
  'GET /Unsuccessful': {
    view: 'Unsuccessful'
  },
  "GET /downloadlink" :"FileController.downloadlink",
  "GET /DuplicateFile": {
    view: 'DuplicateFile'
  },
  /***************************************************************************
  *                                                                          *
  * More custom routes here...                                               *
  * (See https://sailsjs.com/config/routes for examples.)                    *
  *                                                                          *
  * If a request to a URL doesn't match any of the routes in this file, it   *
  * is matched against "shadow routes" (e.g. blueprint routes).  If it does  *
  * not match any of those, it is matched against static assets.             *
  *                                                                          *
  ***************************************************************************/


};
