const fs = require('fs');
const readline = require('readline');
const crypto = require('crypto');
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

function decrypt(_text, _password, _ivkeyword){
    const key = shake256(sha512(_password), 16);
    const iv = shake256(sha256(_ivkeyword), 8); 
    const de = crypto.createDecipheriv(ALGORITHM, key, iv);
    let rs = de.update(_text, 'hex', 'utf8') + de.final('utf8');
    return rs;
}

(async function Main () { // storage <mode:(encrypt|decrypt)> <file>
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    const question = (quest) => new Promise((resolve, reject) => rl.question(quest, (answer) => resolve(answer.trim().toUpperCase())));
    const args = process.argv.slice(2);
    let mode, file, content, destinationFile, password, ivkeyword, readMode, writeMode;
    const help = `
    Usage: 
        safe-storage <mode> <originFile> <destinationFile> [readMode-writeMode]

        > Valid modes are [-e | --encrypt] and [-d | --decrypt];
        > The <readMode-writeMode> parameter, controls the input and output types of the program.
          The default is 'text-bin' for encryption (reads plaintext and saves binary encrypted content) and
          'bin-text' for decryption (reads binary encrypted content, and saves plaintext decrypted content).
          The options are: bin-bin, bin-text, text-bin, text-text.
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
            if (args.length < 3) { throw new Error('ERR:FAR'); }
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
                destinationFile = format(args[2]);
                
                [ readMode, writeMode ] = (() => {
                    let a;
                    if (!args[3]) {
                        if (mode === 'encrypt') a = ['text','bin'];
                        else a = ['bin','text'];
                    } else {
                        a = format(args[3]).split('-'); 
                    }
                    if (!['bin','text'].includes(a[0]) || !['bin','text'].includes(a[1])) throw new Error('ERR:IIO');
                    return a;
                })();
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
            // readMode makes no difference in encryption
            try { content = fs.readFileSync(file); } catch (err) { throw new Error('ERR:IFR'); }
            const encrypted = encrypt(content, password, ivkeyword); 
            if (writeMode === 'text') {
                fs.writeFileSync(destinationFile, encrypted);
            } else {
                fs.writeFileSync(destinationFile, Buffer.from(encrypted,'hex'));
            }
        
        } else if (mode === 'decrypt') {
            try { 
                if (readMode === 'text') content = fs.readFileSync(file, 'hex');
                else content = fs.readFileSync(file);
            } catch (err) { throw new Error('ERR:IFR'); }
            const decrypted = decrypt(content, password, ivkeyword);
            if (writeMode === 'text') { 
                fs.writeFileSync(destinationFile, decrypted);
            } else { 
                fs.writeFileSync(destinationFile, Buffer.from(decrypted,'hex'));
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