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

// function genKeyPair() {

//     // Generates an object where the keys are stored in properties `privateKey` and `publicKey`
//     const keyPair = crypto.generateKeyPairSync('rsa', {
//         modulusLength: 2048, // bits - standard for RSA keys
//         publicKeyEncoding: {
//             type: "spki",
//             format: 'pem' // Most common formatting choice
//         },
//         privateKeyEncoding: {
//             type: "pkcs1",
//             format: 'pem',
//             //   cipher: 'aes-256-cbc',
//             //   passphrase: 'top secret',
//         }
//     });

//     // Create the public key file
//     pubKey = keyPair.publicKey;

//     // Create the private key file
//     priKey = keyPair.privateKey;
// }

// // Generate the keypair
// genKeyPair();
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
fs.writeFileSync('private_key.pem', priKey, (err) => {
    if (err) {
        console.error('Error writing private key to file:', err);
    } else {
        console.log('Private key saved to private_key.pem');
    }
});
var pub = new NodeRSA(pubKey, "pkcs8-public");
var pri = new NodeRSA(priKey, "pkcs8-private");
var publicKey = fs.readFileSync('public_key.pem', "utf-8");

var privateKey = fs.readFileSync('private_key.pem', "utf8");


module.exports = {

 
    LoginPage: async function (req, res) {
        // console.log(pub)
        // console.log(pri)
        return res.view("../views/Login.ejs")

    },
    // EncryptFileWithPub: async function (req, res) {


    //     console.log(priKey, " ", req.body.encrypt)
    //     var decryptedobj = jsdecrypt.dec(priKey, req.body.encrypt);
    //     console.log(decryptedobj)

    //     // var decryptedfilename = jsdecrypt.dec(priKey, req.body.encryptedfilename);
    //     // var hashfilename = crypto.createHash('sha1')
    //     //     .update(decryptedfilename).digest('hex');
    //     // console.log(hashfilename)
    //     // var path = "../Server/assets/images/";
    //     // fs.writeFile(path + "" + hashfilename + "." + req.body.filetype, req.body.encryptedContent, function (err) {
    //     //     if (err) return res.status(400).json("UnSuccessful saving, please upload again");
    //     //     return res.status(200).json({ filepath: hashfilename, msg: "Successfully encrypted and saved, please remember the filename and the password for future decryption" })
    //     // });
    // },
    // EncryptFile: async function (req, res) {
    //     console.log("hello")
    //     console.log(req.body)
    //     var path = "../Server/assets/images/";
    //     // var fd = fs.openSync(path, flag, options.mode);

    //     // console.log(fs.existsSync(path));
    //     // fs.writeFile(req.body.filename, req.body.filecontent, err => {
    //     //     if (err) {
    //     //         console.log(err)
    //     //         return res.status(400).json("UnSuccessful saving, please upload again")
    //     //        } else {
    //     //         return res.status(200).json("Successfully encrypted and saved, please remember the filename and the password for future decryption")


    //     //     }
    //     var hashfilename = crypto.createHash('sha1')
    //         .update(req.body.filename).digest('hex');

    //     console.log(hashfilename);
    //     var pathpath = path + "" + req.body.filename + "." + req.body.filetype
    //     console.log(pathpath)
    //     //   });
    //     fs.appendFile(path + "" + hashfilename + "." + req.body.filetype, req.body.filecontent, function (err) {
    //         if (err) return res.status(400).json("UnSuccessful saving, please upload again");
    //         return res.status(200).json("Successfully encrypted and saved, please remember the filename and the password for future decryption")
    //     });


    // },
    // DecryptFile2: async function (req, res) {
    //     return res.redirect("../test")
    // },
    // // DecryptFile: async function (req, res) {
    // //     return res.view("../views/404.ejs", { publicKey: pubKey })
    // //     // console.log("hello")
    // //     // console.log(req.body)


    // //     // var decryptedpw = jsdecrypt.dec(priKey, req.body.Password);
    // //     // var decryptedpassword = decryptedpw.toString(CryptoJS.enc.Utf8);
    // //     // const pass = CryptoJS.SHA3(decryptedpassword);
    // //     // var decryptedname = jsdecrypt.dec(priKey, req.body.filename);
    // //     // var decryptedfilename = decryptedname.toString(CryptoJS.enc.Utf8);

    // //     // var encryptedfilename = CryptoJS.RC4.encrypt(CryptoJS.lib.WordArray.create(decryptedfilename), pass).toString();
    // //     // console.log(encryptedfilename);
    // //     // var hashfilename = crypto.createHash('sha1')
    // //     //     .update(encryptedfilename).digest('hex');

    // //     // console.log(hashfilename);
    // //     // var path = "../Server/assets/images/" + hashfilename + "." + decryptedfilename.split(".")[1];
    // //     // var filefile = path;
    // //     // var contentcheck;
    // //     // return res.status(200).json("hello")
    // //     // // try{fs.existsSync(filefile)}catch(err){return res.status(400).json({msg:"Unable to retrieve file, please verify your inputs"})}
    // //     // function readDemo1(file1) {
    // //     //     return new Promise(function (resolve, reject) {
    // //     //         fs.readFile(file1, 'utf8', function (err, dataDemo1) {
    // //     //             if (err)
    // //     //                 resolve(null);
    // //     //             else
    // //     //                 resolve(dataDemo1);
    // //     //         });
    // //     //     });
    // //     // }
    // //     // const content =  await readDemo1(filefile)
    // //     // console.log(content);
    // //     // if(content == null){
    // //     //     return res.status(400).json({ msg: "Unable to retrieve file, please ensure your input." })

    // //     // }
    // //     // var orgdata = fs.readFileSync(filefile,'utf8', (err, data) => {
    // //     //     if (err) {
    // //     //         console.log(err)
    // //     //     }
    // //     // });
    // //     // console.log(orgdata)
    // //     // var decryptedfilecontent = CryptoJS.RC4.decrypt({
    // //     //     ciphertext: CryptoJS.enc.Base64.parse(orgdata)
    // //     // }, pass).toString(CryptoJS.enc.Utf8);;
    // //     // console.log(decryptedfilename)
    // //     // console.log(decryptedfilecontent)
    // //     // var newpath = "../Server/assets/images/" + decryptedfilename

    // //     // fs.appendFile(newpath, decryptedfilecontent, function (err) {
    // //     //     if (err) return res.status(400).json({ msg: "Unable to retrieve file, please ensure your input." })

    // //     //     return res.status(200).json("Successfully encrypted and saved, please remember the filename and the password for future decryption")
    // //     // });





    // // },




    // DecryptFileWithPub: async function (req, res) {
    //     console.log(req.body)
    //     function decdec(key, data) {
    //         return jsdecrypt.dec(key, data)
    //     }
    //     var decryptedfilename = decdec(priKey, req.body.filename);
    //     var hashfilename = crypto.createHash('sha1')
    //         .update(decryptedfilename).digest('hex');
    //     console.log(decryptedfilename)

    //     console.log(hashfilename);
    //     var path = "../Server/assets/images/";
    //     var orgfile = path + hashfilename + "." + req.body.filetype;
    //     function readDemo1(file1) {
    //         return new Promise(function (resolve, reject) {
    //             fs.readFile(file1, 'utf8', function (err, dataDemo1) {
    //                 if (err)
    //                     resolve(null);
    //                 else
    //                     resolve(dataDemo1);
    //             });
    //         });
    //     }
    //     var orgdata = await readDemo1(orgfile);


    //     // console.log(priKey)


    //     if (orgdata != null) {

    //         var orgfile = path + hashfilename + "." + req.body.filetype;
    //         var orgdata = fs.readFileSync(orgfile, 'utf8');
    //         // var decryptedfilecontent = decdec(priKey, orgdata);

    //         var decrypted = jsdecrypt.dec(priKey, orgdata.toString(CryptoJS.enc.Utf8));
    //         console.log(orgdata.toString("base64"))
    //         console.log(priKey.trim())
    //         console.log(pubKey.trim())
    //         return res.status(200).json({ file: orgfile, msg: "Successfully retrieve file from server, file will be decrpyted for download and will be removed in server." })
    //     } else {
    //         return res.status(400).json({ msg: "Unable to retrieve file, please ensure your input." })
    //     }
    // },

    // importKey: async function (req, res) {
    //     fs.readFileSync('public_key.pem', (err, public_key) => {
    //         fs.readFileSync('private_key.pem', (err, private_key) => {

    //             return res.status(200).json({ publicKey: public_key, privateKey: private_key })
    //         });
    //     });

    // },

    // EncryptPW: async function (req, res) {
    //     console.log(req.body)
    //     var pass = req.body.passphrase
    //     var filedata = req.body.fileData;
    //     var filename = req.body.filename;
    //     var encrptedfiledata = CryptoJS.AES.encrypt(filedata, pass).toString();
    //     var decrptedfiledata = CryptoJS.AES.decrypt(encrptedfiledata, pass).toString(CryptoJS.enc.Utf8);
    //     console.log(decrptedfiledata)
    //     req.file('file').upload({
    //         // Set the directory where the file will be uploaded
    //         dirname: require('path').resolve(sails.config.appPath, 'assets/uploads'),

    //     }, async (err, uploadedFiles) => {
    //         if (err) {
    //             return res.serverError(err);
    //         }

    //         if (uploadedFiles.length === 0) {
    //             return res.badRequest('No file was uploaded');
    //         }

    //         try {
    //             const file = uploadedFiles[0];
    //             const data = fs.readFileSync(file.fd);
    //             let inputFile = fs.readFileSync(file.fd);
    //             var encrptedfiledata = CryptoJS.AES.encrypt(inputFile, pass);
    //             var decrptedfiledata = CryptoJS.AES.decrypt(encrptedfiledata, pass);
    //             // var decrptedfiledata = CryptoJS.AES.decrypt(encrptedfiledata, pass).toString(CryptoJS.enc.Utf8);
    //             console.log("checkdede", decrptedfiledata)
    //             fs.writeFileSync("../Server/assets/uploadwithPW/2" + filename, Buffer.from(encrptedfiledata, "base64"));
    //             // console.log(file)
    //         } catch (err) {

    //         }
    //     })



    //     var hashedfilename = crypto.createHash('sha1')
    //         .update(filename + "" + pass).digest('hex');
    //     console.log("hashedfilename ", hashedfilename)
    //     var newBlob = new Blob([encrptedfiledata], { type: req.body.filetype })
    //     const bufferToText = (buffer) => {
    //         const bufferByteLength = buffer.byteLength;
    //         const bufferUint8Array = new Uint8Array(buffer, 0, bufferByteLength);

    //         return new TextDecoder().decode(bufferUint8Array);
    //     };
    //     const buffer = await newBlob.arrayBuffer();

    //     var path = "../Server/assets/uploadwithPW/" + filename
    //     fs.writeFileSync(path, bufferToText(buffer), (err) => {
    //         if (err) throw err;
    //         console.log("written")
    //     });
    //     console.log("hello")
    //     return res.view("../views/Success.ejs")

    // },

    upload: async function (req, res) {
        // The public key should be in PEM format

        // Initialize the RSA key with the public key
        // const key = new NodeRSA(pubKey,"pkcs8-public");

        const key = keyP;
        const prikey = pri;

        req.file('file').upload({
            // Set the directory where the file will be uploaded
            dirname: require('path').resolve(sails.config.appPath, 'assets/uploads'),

        }, async (err, uploadedFiles) => {
            if (err) {
                return res.serverError(err);
            }

            if (uploadedFiles.length === 0) {
                return res.badRequest('No file was uploaded');
            }

            try {
                const file = uploadedFiles[0];
                const data = fs.readFileSync(file.fd);
                // console.log(file.fd)

                // Encrypt the file data with the public key
                console.log( "readdata", data )

                // console.log("encrptydata", encrypted)
                // console.log(
                //     "filename", file.filename
                // )
                // You may want to store the encrypted data in a file or send it over the network


                var hashedfilename = crypto.createHash('sha1')
                    .update(file.filename).digest('hex');
                // console.log(hashedfilename)
                const encryptedFilePath = "../Server/assets/uploads/" + hashedfilename + "." + file.filename.split(".")[1];
                // console.log(encryptedFilePath)
                let inputFile = fs.readFileSync(file.fd);
                // const encrypted = key.encrypt(data, "base64");
                const encryptedfile = key.encrypt(Buffer.from(inputFile), "base64");
                console.log(encryptedfile)
                console.log(atob(prikey.decrypt(encryptedfile, "base64")))

                //   const encryptedfile = key.encrypt(inputFile, "base64");
                fs.writeFileSync("../Server/assets/uploads/2" + hashedfilename + "." + file.filename.split(".")[1], encryptedfile);
                // fs.writeFileSync("../Server/assets/uploads/2" + hashedfilename + "." + file.filename.split(".")[1], encryptedfile.toString());
                fs.unlinkSync(file.fd);

                // fs.writeFileSync(encryptedFilePath, encrypted.toString("base64"), 'base64');
                // fs.renameSync(file.fd, "../Server/assets/uploads/2" + hashedfilename + "." + file.filename.split(".")[1], (err) => {
                //     if (err) throw err;
                //     // fs.writeFileSync("../Server/assets/uploads/2" + hashedfilename + "." + file.filename.split(".")[1], encryptedfile.toString());
                //     var input = fs.readFileSync("../Server/assets/uploads/2" + hashedfilename + "." + file.filename.split(".")[1])
                //     console.log(input.toString())
                //     console.log('Rename complete! ', encryptedFilePath);
                // })
                //   fs.writeFileSync(encryptedFilePath, encrypted.toString("base64"), 'base64');
                return res.view("../views/Success.ejs", {
                    type: "PubEn",
                    message: 'File encrypted and uploaded successfully!',

                });
            } catch (encryptionError) {
                return res.serverError(encryptionError);
            }
        });
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
                    fs.writeFileSync("../Server/assets/download/2" + filename, decrypted2);

                    const mimeType = mime.lookup(path);
                    console.log(mimeType);
                    console.log(path)
                    const blob = new Blob([decrypted2], { type: mimeType })
                    console.log(blob)

                    return res.redirect("/downloadlink?path=" + path)
            

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
            fs.writeFileSync("../Server/assets/downloadwithPW/2" + filename, Buffer.from(decrptydata3, "base64"));
           
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

            return res.redirect("/downloadlink?path=" + path)

            return res.status(200).json({ pathto: '../views/SuccessDownload', bytes: debytes, filename: filename })
        } else {
            return res.view('../views/Unsuccessful')
        }







    },
    // api/controllers/FileController.js



    uploadwithPW: async function (req, res) {

        console.log(req.query.PW)

        var filefile = req.file('file')

        filefile.upload({
            // set the directory where the files will be uploaded
            dirname: require('path').resolve(sails.config.appPath, 'assets/uploadwithPW')
        }, function (err, uploadedFiles) {
            if (err) return res.negotiate(err);;

            // If no files were uploaded, respond with an error.
            if (uploadedFiles.length === 0) {
                return res.badRequest('No file was uploaded');
            }
            const file = uploadedFiles[0];
            const data = fs.readFileSync(file.fd);

            // console.log(uploadedFiles.length)
            // console.log(uploadedFiles);
            // console.log(file.size)

            // // console.log(req.file('passphrase'))
            // console.log(data.toString('base64'))
            var passphrase = req.query.PW;
            // console.log(passphrase)
            const encrypted = CryptoJS.AES.encrypt(data.toString('base64'), passphrase).toString();
            let inputFile = fs.readFileSync(file.fd);
            var org = inputFile.toString('base64');



            console.log("org ", inputFile.toString('base64'))
            var encrptedfiledata = CryptoJS.AES.encrypt(inputFile.toString('base64'), passphrase);
            // var encrypteded = encrptedfiledata.toString()
            console.log("encrptydata", encrptedfiledata)
           
            // var decrptydata2 = decrptedfiledata.toString(CryptoJS.enc.Base64);

            // console.log("decrptydata2", decrptydata2) 
            var decrptedfiledata = CryptoJS.AES.decrypt(encrptedfiledata, passphrase);
            const decodedString = atob(decrptedfiledata.toString(CryptoJS.enc.Base64));
            var decrptydata3 = decodedString;
            console.log("decrptydata3", decrptydata3)
            const decodedString2 = atob(decodedString);

            var decrptydata4 = decodedString2;
            console.log("decrpty data4", decodedString2)
            var hashedfilename = crypto.createHash('sha1')
                .update(file.filename + "" + passphrase).digest('hex');

            // fs.writeFileSync("../Server/assets/uploadwithPW/org3" + hashedfilename + "." + file.filename.split(".")[1], Buffer.from(decrptydata3, "base64"));
            // if(decrptydata4 == atob(data.toString("base64"))){
            //     console.log("check and org same ,\n" ,decrptydata4,  atob(data.toString("base64")))
            // }else{
            //     console.log("check not org same ,\n" ,decrptydata4, atob(data.toString("base64")))
            // }

            //     fs.writeFileSync("../Server/assets/uploadwithPW/check" + hashedfilename + "." + file.filename.split(".")[1],  Buffer.from( atob(data.toString("base64"))) );
            //     inputFile = fs.readFileSync("../Server/assets/uploadwithPW/check" + hashedfilename + "." + file.filename.split(".")[1]);
            // // console.log("finalresult",inputFile.toString('base64'))
            // fs.writeFileSync("../Server/assets/uploadwithPW/org"+ hashedfilename + "." + file.filename.split(".")[1],decrptydata4);
            fs.writeFileSync("../Server/assets/uploadwithPW/2" + hashedfilename + "." + file.filename.split(".")[1], encrptedfiledata.toString());
            // inputFile = fs.readFileSync("../Server/assets/uploadwithPW/org" + hashedfilename + "." + file.filename.split(".")[1]);
            // console.log(data.toString("base64") == inputFile.toString("base64"))
            // var decrptedfiledata = CryptoJS.AES.encrypt(encrptedfiledata.toString('base64'), passphrase).toString();;
            fs.unlinkSync(file.fd);
            console.log("../Server/assets/uploadwithPW/2" + hashedfilename + "." + file.filename.split(".")[1])



            // Get the passphrase from the body

            // var hashedfilename = crypto.createHash('sha1')
            //     .update(file.filename + "" + passphrase).digest('hex');
            // var path = "../Server/assets/uploadwithPW/" + hashedfilename + "." + file.filename.split(".")[1]
            // // TODO: Do something with the passphrase and file information
            // console.log('Passphrase:', passphrase);
            // console.log('File Details:', file);

            // fs.rename(file.fd, path, (err) => {
            //     if (err) throw err;
            //     fs.writeFileSync(path, encrypted.toString("base64"), 'utf8');
            //     console.log('Rename complete!');
            // })
            // // Respond with the information of the file(s) that were uploaded.
            return res.redirect("/Success");
        }).on('finish', function onSuccess() {
            console.log("here")
        });



    },
    downloadlink: function (req, res) {
        // Define the file path or compute it based on some logic
        // For example, this might be './assets/uploads/myfile.txt'
        console.log(req.query.path)
        const filePath = require('path').resolve(sails.config.appPath, req.query.path);

        // Set the filename that will be suggested to the client
        const fileName = require('path').basename(filePath);

        // Use the res.attachment() method to set the Content-Disposition header
        // and res.sendFile() to send the file
        res.attachment(fileName);
        const options = {
            root: "../views/SuccessDownload"
        };
        res.sendFile(fileName, options, function (err) {
            if (err) {
                console.error('Error sending file:', err);
            } else {
                console.log('Sent:', fileName);
            }
        });
        // Stream the file down
        const downloading = require('fs').createReadStream(filePath);

        downloading.on('error', (err) => {
            // Handle error, make sure to handle the case where the client aborted the connection
            return res.serverError(err);
        });

        downloading.pipe(res);
    },


    SuccessDownload: async function (req, res) {



        console.log(req.body);
        return res.view("/views/SuccessDownload", { filename: req.body.filename, filecontent: bytes })
    },
}


