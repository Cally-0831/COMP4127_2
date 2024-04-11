const CryptoJS = require("crypto-js");
// const fs = require('node:fs');
const path = require('path');
const fs = require('fs');
const NodeRSA = require('node-rsa');
const { generateKeyPair } = require('crypto');
var crypto = require('crypto')
const { Buffer } = require('buffer');
var jsdecrypt = require('jsdecrypt');
var { ncrypt } = require("ncrypt-js");
const languageEncoding = require("detect-file-encoding-and-language");
var chardet = require('chardet');
const { Blob } = require('buffer');
const multer = require('multer');
const upload = multer({ dest: 'uploads/' });
const mime = require('mime-types');
const FileType = require('file-type');
const Writable = require('stream').Writable;



var priKey;
var pubKey;

const directory1 = "../Server/assets/uploadwithPW/";
const directory2 = "../Server/assets/downloadwithPW/";
const directory3 = "../Server/assets/uploads/";
const directory4 = "../Server/assets/download/";

function removefile() {
    fs.readdir(directory1, (err, files) => {
        if (err) throw err;

        for (const file of files) {
            fs.unlink(path.join(directory1, file), (err) => {
                if (err) throw err;
            });
        }
    })
    fs.readdir(directory2, (err, files) => {
        if (err) throw err;

        for (const file of files) {
            fs.unlink(path.join(directory2, file), (err) => {
                if (err) throw err;
            });
        }
    })
    fs.readdir(directory3, (err, files) => {
        if (err) throw err;

        for (const file of files) {
            fs.unlink(path.join(directory3, file), (err) => {
                if (err) throw err;
            });
        }
    })
    fs.readdir(directory4, (err, files) => {
        if (err) throw err;

        for (const file of files) {
            fs.unlink(path.join(directory4, file), (err) => {
                if (err) throw err;
            });
        }
    })

}
removefile();


const keyP = new NodeRSA({ b: 512 });
pubKey = keyP.exportKey('pkcs8-public');
priKey = keyP.exportKey('pkcs8-private');
fs.writeFileSync('public_key.pem', pubKey, (err) => {
    if (err) {
        console.error('Error writing public key to file:', err);
    } else {
        console.log('Public key saved to public_key.pem');
    }
});
// fs.writeFileSync('private_key.pem', priKey, (err) => {
//     if (err) {
//         console.error('Error writing private key to file:', err);
//     } else {
//         console.log('Private key saved to private_key.pem');
//     }
// });
var pub = new NodeRSA(pubKey, "pkcs8-public");
var pri = new NodeRSA(priKey, "pkcs8-private");
var publicKey = fs.readFileSync('public_key.pem', "utf-8");

// var privateKey = fs.readFileSync('private_key.pem', "utf8");



module.exports = {


    LoginPage: async function (req, res) {
        // console.log(pub)
        // console.log(pri)
        return res.view("../views/Login.ejs", { pubKey: pubKey })

    },
  
    upload: async function (req, res) {
        // The public key should be in PEM format


        // Initialize the RSA key with the public key
        // const key = new NodeRSA(pubKey,"pkcs8-public");
        console.log(req.body)
        const key = keyP;
        const prikey = pri;
        const stringToArrayBuffer = (string) => {
            let byteArray = new Uint8Array(string.length);
            for (var i = 0; i < string.length; i++) {
                byteArray[i] = string.codePointAt(i);
            }
            return byteArray;
        }


        var buf = stringToArrayBuffer(req.body.filecontent)
        console.log(buf.toString())


        var hashedfilename = crypto.createHash('sha1')
            .update(req.body.filename).digest('hex');
        const encryptedFilePath = "../Server/assets/uploads/2" + hashedfilename + "." + req.body.filename.split(".")[1]
        console.log(encryptedFilePath)
        if (!fs.existsSync(encryptedFilePath)) {
            const encryptedfile = key.encrypt(Buffer.from(req.body.filecontent), "base64");
            console.log(encryptedfile)
            console.log(atob(prikey.decrypt(encryptedfile, "base64")))

            fs.writeFileSync("../Server/assets/uploads/2" + hashedfilename + "." + req.body.filename.split(".")[1], encryptedfile);
            return res.status(200).json({ path: "/Success" })
        } else {
            return res.status(400).json({ path: "/DuplicateFile" })
        }




        // console.log(req.file('file').UploadStream)
        // req.file('file').upload({
        //     // Set the directory where the file will be uploaded
        //     dirname: require('path').resolve(sails.config.appPath, 'assets/uploads'),

        // }, async (err, uploadedFiles) => {
        //     if (err) {
        //         return res.serverError(err);
        //     }

        //     if (uploadedFiles.length === 0) {
        //         return res.badRequest('No file was uploaded');
        //     }

        //     try {
        //         const file = uploadedFiles[0];
        //         const data = fs.readFileSync(file.fd);
        //         console.log(file.fd)

        //         // Encrypt the file data with the public key
        //         console.log("readdata", data.toString())

        //         // console.log("encrptydata", encrypted)
        //         // console.log(
        //         //     "filename", file.filename
        //         // )
        //         // You may want to store the encrypted data in a file or send it over the network


        //         var hashedfilename = crypto.createHash('sha1')
        //             .update(file.filename).digest('hex');
        //         // console.log(hashedfilename)
        //         const encryptedFilePath = "../Server/assets/uploads/2" + hashedfilename + "." + file.filename.split(".")[1]
        //         console.log(encryptedFilePath)
        //         if (!fs.existsSync(encryptedFilePath)) {
        //             let inputFile = fs.readFileSync(file.fd);
        //             // const encrypted = key.encrypt(data, "base64");
        //             const encryptedfile = key.encrypt(Buffer.from(inputFile), "base64");
        //             console.log(encryptedfile)
        //             console.log(atob(prikey.decrypt(encryptedfile, "base64")))

        //             //   const encryptedfile = key.encrypt(inputFile, "base64");
        //             fs.writeFileSync("../Server/assets/uploads/2" + hashedfilename + "." + file.filename.split(".")[1], encryptedfile);
        //             // fs.writeFileSync("../Server/assets/uploads/2" + hashedfilename + "." + file.filename.split(".")[1], encryptedfile.toString());
        //             fs.unlinkSync(file.fd);
        //             return res.view("../views/Success.ejs", {
        //                 type: "PubEn",
        //                 message: 'File encrypted and uploaded successfully!',

        //             });
        //         } else {
        //             fs.unlinkSync(file.fd);
        //             return res.view("../views/DuplicateFile.ejs")
        //         }


        //         // fs.writeFileSync(encryptedFilePath, encrypted.toString("base64"), 'base64');
        //         // fs.renameSync(file.fd, "../Server/assets/uploads/2" + hashedfilename + "." + file.filename.split(".")[1], (err) => {
        //         //     if (err) throw err;
        //         //     // fs.writeFileSync("../Server/assets/uploads/2" + hashedfilename + "." + file.filename.split(".")[1], encryptedfile.toString());
        //         //     var input = fs.readFileSync("../Server/assets/uploads/2" + hashedfilename + "." + file.filename.split(".")[1])
        //         //     console.log(input.toString())
        //         //     console.log('Rename complete! ', encryptedFilePath);
        //         // })
        //         //   fs.writeFileSync(encryptedFilePath, encrypted.toString("base64"), 'base64');

        //     } catch (encryptionError) {
        //         return res.serverError(encryptionError);
        //     }
        // });
    },

    download: function (req, res) {
        var filename = req.body.filename
        console.log(req.body)

        var hashedfilename = crypto.createHash('sha1')
            .update(filename).digest('hex');
        console.log("in download", hashedfilename)
        const encryptedFilePath = "../Server/assets/uploads/2" + hashedfilename + "." + filename.split(".")[1];


        const key = keyP

        if (fs.existsSync(encryptedFilePath)) {
            console.log("file exists")
            var encoding = chardet.detectFileSync(encryptedFilePath);
            console.log("encodeing scheme ", encoding)
            fs.readFile(encryptedFilePath, async function (err, encryptedData) {
                if (err) {
                    return res.serverError(err);
                }
                try {

                    let inputFile = fs.readFileSync("../Server/assets/uploads/2" + hashedfilename + "." + filename.split(".")[1]);
                    console.log(inputFile.toString())
                    const decryptedfile = keyP.decrypt(inputFile.toString(), "base64");
                    console.log(decryptedfile)
                    var path = "../Server/assets/download/2" + filename
                    var decrypted2 = Buffer.from(decryptedfile, "base64");
                    // fs.writeFileSync("../Server/assets/download/2" + filename, decrypted2);
                    var filetype = await FileType.fromBuffer(decrypted2);
                    const mimeType = mime.lookup(path);
                    console.log(mimeType);
                    console.log(path)
                    const blob = new Blob(decrypted2, { type: filetype })

                    // Assuming 'blob' is the Blob object you created
                    // const blob = new Blob([fileData], { type: 'application/octet-stream' });

                    // // Create a link element
                    // const link = document.createElement('a');
                    // // Create a URL for the blob
                    // const url = URL.createObjectURL(blob);

                    // link.href = url;
                    // link.download =filename; // You can give a default name, but the extension is unknown

                    // // Append the link to the body (usually not necessary to add it to the DOM to trigger the download)
                    // document.body.appendChild(link);

                    // // Programmatically click the link to trigger the download
                    // link.click();

                    // // Clean up by revoking the Object URL and removing the link element
                    // URL.revokeObjectURL(url);
                    // document.body.removeChild(link);

                    // return res.redirect("/downloadlink?path=" + path)
                    var filenamename = filename
                    console.log(filename, "\n", decrypted2)
                    fs.unlinkSync("../Server/assets/uploads/2" + hashedfilename + "." + filename.split(".")[1]);
                    return res.view("../views/SuccessDownload", {
                        filenamename: filenamename, filecontent: decrypted2
                    })

                } catch (decryptionError) {
                    return res.serverError(decryptionError);
                }

            });

        } else {
            return res.view('../views/Unsuccessful')
        }

    },

    downloadwithPW: async function (req, res) {
        console.log(req.body)
        var pass = req.body.passphrase;
        var filename = req.body.filename;
        pass = crypto.createHash('sha1')
            .update(pass).digest('hex');

        // var encrptedfiledata = CryptoJS.RC4.encrypt(filedata, pass).toString();
        var hashedfilename = crypto.createHash('sha1')
            .update(filename + "" + pass).digest('hex');
        hashedfilename += "." + filename.split(".")[1];
        console.log("hashedfilename ", hashedfilename)
        var path = "../Server/assets/uploadwithPW/" + hashedfilename;
        var path2 = "../Server/assets/uploadwithPW/2" + hashedfilename;
        console.log("path1 ", path)
        console.log("path2 ", path2)




        if (fs.existsSync(path2)) {
            console.log("file exits")
            // var text = fs.readFileSync(path)
            var text2 = fs.readFileSync(path2)
            // console.log(text.toString(), "\n", text2.toString())
            // var bytes = CryptoJS.AES.decrypt(text.toString(), pass);

            // var cipherBytes = CryptoJS.enc.Base64.parse(text2);

            var decrptedfiledata = CryptoJS.AES.decrypt(text2.toString(), pass);
            const decodedString = atob(decrptedfiledata.toString(CryptoJS.enc.Base64));
            var decrptydata3 = decodedString;
            console.log("decrptydata3", decrptydata3)
            // const decodedString2 = atob(decodedString);
            // console.log( debytes.toString())
            // const decodedString = atob(debytes.toString(CryptoJS.enc.Base64));
            // const decodedString = atob(decrptedfiledata.toString(CryptoJS.enc.Base64));
            // var decrptydata3 = decodedString;
            // fs.writeFileSync("../Server/assets/downloadwithPW/2" + filename, Buffer.from(decrptydata3, "base64"));

            // console.log("decrptydata in download", decodedString.toString("base64"))
            // var decrypted2 = Buffer.from(debytes.toString(), "base64");
            // fs.writeFileSync("../Server/assets/download/2" + filename, decrypted2);
            // fs.writeFileSync("../Server/assets/downloadwithPW/" + filename, decodedString);
            // fs.writeFileSync("../Server/assets/downloadwithPW/2" + filename, decodedString);

            console.log("../Server/assets/downloadwithPW/2" + filename)
            //    var dede =  new TextDecoder().decode(await decrptyed.arrayBuffer())
            //    return res.view('../views/SuccessDownload',{filename : filename, bytes:bytes})

            const mimeType = mime.lookup("../Server/assets/downloadwithPW/2" + filename);
            console.log(mimeType);
            console.log(path)
            path = "../Server/assets/downloadwithPW/2" + filename
            const blob = new Blob([decodedString], { type: mimeType })
            console.log(blob)
            var filenamename = filename
            console.log(filename, "\n", decodedString)
            fs.unlinkSync("../Server/assets/uploadwithPW/2" + hashedfilename);

            return res.view("../views/SuccessDownload2", {
                filenamename: filenamename, filecontent: decodedString
            })
            return res.redirect("/downloadlink?path=" + path)

            return res.status(200).json({ pathto: '../views/SuccessDownload', bytes: debytes, filename: filename })
        } else {
            return res.view('../views/Unsuccessful')
        }







    },
   

    uploadwithPW: async function (req, res) {
        console.log(req.body)
        var passphrase = crypto.createHash('sha1')
            .update(req.body.passphrase).digest('hex');
        var hashedfilename = crypto.createHash('sha1')
            .update(req.body.filename + "" + passphrase).digest('hex');
        var path = "../Server/assets/uploadwithPW/2" + hashedfilename + "." + req.body.filename.split(".")[1]
        if (!fs.existsSync(path)) {



            var encrptedfiledata = CryptoJS.AES.encrypt(req.body.filecontent.toString('base64'), passphrase);
            console.log("encrptydata", encrptedfiledata.toString())

            // varecrptydata2", decrptydata2) 
            var decrptedfiledata = CryptoJS.AES.decrypt(encrptedfiledata, passphrase);
            const decodedString = atob(decrptedfiledata.toString(CryptoJS.enc.Base64));
            var decrptydata3 = decodedString;
            console.log("decrptydata3", decrptydata3)
            const decodedString2 = atob(decodedString);

            var decrptydata4 = decodedString2;
            console.log("decrpty data4", decrptydata4)
            var hashedfilename = crypto.createHash('sha1')
                .update(req.body.filename + "" + passphrase).digest('hex');

            // fs.wri/assets/uploadwithPW/org"+ hashedfilename + "." + file.filename.split(".")[1],decrptydata4);
            fs.writeFileSync("../Server/assets/uploadwithPW/2" + hashedfilename + "." + req.body.filename.split(".")[1], encrptedfiledata.toString());

            return res.status(200).json({ path: "/Success" })

        } else {
            return res.status(400).json({ path: "/DuplicateFile" })
        }







        // filefile.upload({
        //     // set the directory where the files will be uploaded
        //     dirname: require('path').resolve(sails.config.appPath, 'assets/uploadwithPW')
        // }, function (err, uploadedFiles) {
        //     if (err) return res.negotiate(err);;

        //     // If no files were uploaded, respond with an error.
        //     if (uploadedFiles.length === 0) {
        //         return res.badRequest('No file was uploaded');
        //     }
        //     const file = uploadedFiles[0];
        //     const data = fs.readFileSync(file.fd);

        //     var passphrase = req.query.PW;
        //     // console.log(passphrase)
        //     passphrase = crypto.createHash('sha1')
        //         .update(passphrase).digest('hex');
        //     var hashedfilename = crypto.createHash('sha1')
        //         .update(file.filename + "" + passphrase).digest('hex');
        //     var path = "../Server/assets/uploadwithPW/2" + hashedfilename + "." + file.filename.split(".")[1]

        //     if (!fs.existsSync(path)) {

        //         // console.log(uploadedFiles.length)
        //         // console.log(uploadedFiles);
        //         // console.log(file.size)

        //         // // console.log(req.file('passphrase'))
        //         // console.log(data.toString('base64'))

        //         const encrypted = CryptoJS.AES.encrypt(data.toString('base64'), passphrase).toString();
        //         let inputFile = fs.readFileSync(file.fd);
        //         var org = inputFile.toString('base64');



        //         console.log("org ", inputFile.toString('base64'))
        //         var encrptedfiledata = CryptoJS.AES.encrypt(inputFile.toString('base64'), passphrase);
        //         // var encrypteded = encrptedfiledata.toString()
        //         console.log("encrptydata", encrptedfiledata)

        //         // var decrptydata2 = decrptedfiledata.toString(CryptoJS.enc.Base64);

        //         // console.log("decrptydata2", decrptydata2) 
        //         var decrptedfiledata = CryptoJS.AES.decrypt(encrptedfiledata, passphrase);
        //         const decodedString = atob(decrptedfiledata.toString(CryptoJS.enc.Base64));
        //         var decrptydata3 = decodedString;
        //         console.log("decrptydata3", decrptydata3)
        //         const decodedString2 = atob(decodedString);

        //         var decrptydata4 = decodedString2;
        //         console.log("decrpty data4", decodedString2)
        //         var hashedfilename = crypto.createHash('sha1')
        //             .update(file.filename + "" + passphrase).digest('hex');

        //         // fs.writeFileSync("../Server/assets/uploadwithPW/org3" + hashedfilename + "." + file.filename.split(".")[1], Buffer.from(decrptydata3, "base64"));
        //         // if(decrptydata4 == atob(data.toString("base64"))){
        //         //     console.log("check and org same ,\n" ,decrptydata4,  atob(data.toString("base64")))
        //         // }else{
        //         //     console.log("check not org same ,\n" ,decrptydata4, atob(data.toString("base64")))
        //         // }

        //         //     fs.writeFileSync("../Server/assets/uploadwithPW/check" + hashedfilename + "." + file.filename.split(".")[1],  Buffer.from( atob(data.toString("base64"))) );
        //         //     inputFile = fs.readFileSync("../Server/assets/uploadwithPW/check" + hashedfilename + "." + file.filename.split(".")[1]);
        //         // // console.log("finalresult",inputFile.toString('base64'))
        //         // fs.writeFileSync("../Server/assets/uploadwithPW/org"+ hashedfilename + "." + file.filename.split(".")[1],decrptydata4);
        //         fs.writeFileSync("../Server/assets/uploadwithPW/2" + hashedfilename + "." + file.filename.split(".")[1], encrptedfiledata.toString());
        //         // inputFile = fs.readFileSync("../Server/assets/uploadwithPW/org" + hashedfilename + "." + file.filename.split(".")[1]);
        //         // console.log(data.toString("base64") == inputFile.toString("base64"))
        //         // var decrptedfiledata = CryptoJS.AES.encrypt(encrptedfiledata.toString('base64'), passphrase).toString();;
        //         fs.unlinkSync(file.fd);
        //         console.log("../Server/assets/uploadwithPW/2" + hashedfilename + "." + file.filename.split(".")[1])
        //         return res.redirect("/Success");


        //     } else {
        //         fs.unlinkSync(file.fd);
        //         return res.view("../views/DuplicateFile.ejs")
        //     }


        // });



    },
    // downloadlink: function (req, res) {
    //     // Define the file path or compute it based on some logic
    //     // For example, this might be './assets/uploads/myfile.txt'
    //     console.log(req.query.path)
    //     const filePath = require('path').resolve(sails.config.appPath, req.query.path);

    //     // Set the filename that will be suggested to the client
    //     const fileName = require('path').basename(filePath);

    //     // Use the res.attachment() method to set the Content-Disposition header
    //     // and res.sendFile() to send the file
    //     res.attachment(fileName);
    //     const options = {
    //         root: "../views/SuccessDownload"
    //     };
    //     res.sendFile(fileName, options, function (err) {
    //         if (err) {
    //             console.error('Error sending file:', err);
    //         } else {
    //             console.log('Sent:', fileName);
    //         }
    //     });
    //     // Stream the file down
    //     const downloading = require('fs').createReadStream(filePath);

    //     downloading.on('error', (err) => {
    //         // Handle error, make sure to handle the case where the client aborted the connection
    //         return res.serverError(err);
    //     });

    //     downloading.pipe(res);
    // },

    SuccessDownload2: async function (req, res) {
        console.log(req.body);
        return res.view("/views/SuccessDownload2", { filename: req.body.filename, filecontent: bytes })
    },
    SuccessDownload: async function (req, res) {
        console.log(req.body);
        return res.view("/views/SuccessDownload", { filename: req.body.filename, filecontent: bytes })
    },
}


