const fs = require('fs');
const readline = require('readline');
const crypto = require('crypto');
const { pipeline } = require('stream/promises');
const ALGORITHM = 'aes-256-cbc';

const format = (str,toLower=true) => (toLower) ? str.toString().trim().toLowerCase() : str.toString().trim();
const sha256 = (value) => crypto.createHash('sha256').update(value).digest('hex');
const sha512 = (value) => crypto.createHash('sha512').update(value).digest('hex');
const shake256 = (value, out) => crypto.createHash('shake256', {outputLength:out}).update(value).digest('hex');

function encrypt(_text, _password, _ivkeyword){
    const key = shake256(sha512(_password), 16);
    const iv = shake256(sha256(_ivkeyword), 8); 
    const ci = crypto.createCipheriv(ALGORITHM, key, iv);
    let rs = ci.update(_text, 'utf8', 'hex') + ci.final('hex');
    return rs;
}

async function encryptFile(_origin, _target, _password, _ivkeyword) {
    const key = shake256(sha512(_password), 16);
    const iv = shake256(sha256(_ivkeyword), 8);
    return await pipeline (
        fs.createReadStream(_origin),
        crypto.createCipheriv(ALGORITHM, key, iv),
        fs.createWriteStream(_target)
    );
}

function decrypt(_text, _password, _ivkeyword){
    const key = shake256(sha512(_password), 16);
    const iv = shake256(sha256(_ivkeyword), 8); 
    const de = crypto.createDecipheriv(ALGORITHM, key, iv);
    let rs = de.update(_text, 'hex', 'utf8') + de.final('utf8');
    return rs;
}

async function decryptFile(_origin, _target, _password, _ivkeyword) {
    const key = shake256(sha512(_password), 16);
    const iv = shake256(sha256(_ivkeyword), 8);
    return await pipeline (
        fs.createReadStream(_origin),
        crypto.createDecipheriv(ALGORITHM, key, iv),
        fs.createWriteStream(_target)
    );
}


(async function Main () { // storage <mode:(encrypt|decrypt)> <file>
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    const question = (quest) => new Promise((resolve, reject) => rl.question(quest, (answer) => resolve(answer.trim().toUpperCase())));
    const args = process.argv.slice(2);
    let mode, file, content, destinationFile, password, ivkeyword, isFile;
    const help = `
    Usage: 
        safe-storage <mode> <originFile> [--file]

        > Valid modes are [-e | --encrypt] and [-d | --decrypt];
        > The [--file] parameter is used to encrypt or decrypt an entire binary (or plain) file, instead of plain data.
        > About encryption method and password:
            > The password you provide for encryption, is hashed with sha512,
              and then with shake256 (in 128-bit-long mode) before being used as a key.
            > The IV keyword you provide for encryption, is hashed with sha256, 
              and then with shake256 (in 64-bit-long mode) before being used as IV.
            > INFO: The basic hashing for password (sha512) is different from the one for ivkeyword (sha256), 
              for a colision-safe encription. This means, that even if the iv keyword and password are the same, 
              the IV and key will be different internally.
    `;

    try {
        // Getting CLI arguments
            if (args.length < 2) { throw new Error('ERR:FAR'); }
            else { 
                mode = (() => {
                    if (['-d','--decrypt'].includes(format(args[0],true))) {
                        return 'decrypt';
                    } else if (['-e','--encrypt'].includes(format(args[0],true))) {
                        return 'encrypt';
                    } else {
                        throw new Error('ERR:IMS');
                    }
                })();
                file = format(args[1]); 
                destinationFile = file + (mode === 'encrypt' ? '.aes' : '.dec');
                isFile = args.map(x => format(x,true)).includes('--file');
            }
        
        // Capturing password
            rl.on('SIGINT', () => { rl.question('Exit (y or n)? ', (input) => { if (input.match(/^y(es)?$/i)) { rl.pause(); process.exit(0); } }); });
            rl.on('SIGTERM', () => { rl.question('Exit (y or n)? ', (input) => { if (input.match(/^y(es)?$/i)) { rl.pause(); process.exit(0); } }); });
            process.stdin.on("keypress", function (c, k) {
                readline.moveCursor(rl.output, -rl.line.length, 0); // move cursor back to the beginning of the input:
                readline.clearLine(rl.output, 1); // clear everything to the right of the cursor:
                for (var i = 0; i < rl.line.length; i++) { rl.output.write("*"); } // replace the original input with asterisks:
            });
            password = await question('>> Input Password: ');
            ivkeyword = await question('>> Input IV Keyword: ');
            rl.close();

        //Parsing input, password and arguments:
        if (mode === 'encrypt') {
            let encrypted;
            if (!isFile) {
                try {
                    content = fs.readFileSync(file, 'utf8');
                    encrypted = encrypt(content, password, ivkeyword); 
                    fs.writeFileSync(destinationFile, encrypted);
                } catch (err) { throw new Error('ERR:IFR'); }
            } else {
                try {
                    await encryptFile(file, destinationFile, password, ivkeyword);
                } catch (err) { throw new Error('ERR:IFR'); }
            }

        } else if (mode === 'decrypt') {
            let decrypted;
            if (!isFile) {
                try {
                    content = fs.readFileSync(file, 'utf8');
                    decrypted = decrypt(content, password, ivkeyword);
                    fs.writeFileSync(destinationFile, decrypted);
                } catch (err) { throw new Error('ERR:IFR'); }
            } else {
                try {
                    await decryptFile(file, destinationFile, password, ivkeyword);
                } catch (err) { throw new Error('ERR:IFR'); }
            }
        }

    } catch (err) {
        let msg = '';
        switch (err.message) {
            case 'ERR:IMS': msg = 'ERROR: INVALID MODE SELECTED'; break;
            case 'ERR:IFR': msg = 'ERROR: WHILE READING PROVIDED FILE'; break;
            case 'ERR:FAR': msg = 'ERROR: LESS ARGUMENTS THAN NECESSARY'; break;
            case 'ERR:IIO': msg = 'ERROR: INVALID I/O MODES PROVIDED'; break;
            default: msg = err.message;
        }
        rl.close();
        return console.log(msg + '\n\n' + help);
    }
})();