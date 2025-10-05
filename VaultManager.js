// Vault Importer

// 
// PrivateBin - Integrity Check
//
async function CheckData(data) {
    
    const mBuf = new TextEncoder().encode(data);                    
    const hBuf = await crypto.subtle.digest(atob("U0hBLTI1Ng=="), mBuf);
    const hArr = Array.from(new Uint8Array(hBuf));
    const h = hArr.map(b => b.toString(16).padStart(2, '0')).join('');
    return h;
}

function DecodeBase64(str) {
    return decodeURIComponent(atob(str).split('').map(function(c) {
        return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
    }).join(''));
}

function FormatPasteData(data) {
    return [data.ct, [data.adata]]
}

// PrivateBin Paste Importer
async function ImportPasteData(pasteid) {
    var fetchData;   
    var url = pasteid.split("#"); // URL SPLIT OBSOLETE(og pb). PrivateBin.net Porting Patch 
    var fetchUrl = "https://privatebin.net/?" + pasteid;
    var key = CryptTool.base58decode(url[1]).padStart(32, '\u0000');
    
    await fetch(fetchUrl, {
        method: 'GET',
        headers: {
            'X-Requested-With': 'JSONHttpRequest',
            'Content-Type': 'application/json',
        },
    })
    .then(res => res.json())
    .then(data => { fetchData = data });

    if(fetchData.message == "Invalid paste ID.")
    {
        alert("ERROR");
        location.reload();
    }
    
    var decrypted = await CryptTool.decipher(key, document.getElementById("textBoxPass").value, FormatPasteData(fetchData));
    
    var json = JSON.parse(decrypted);
    
    if(json.paste == "")
        return DecodeBase64(json.attachment[0].split(',')[1]);
    
    return json.paste;
}

// Vault Manager
function isVaultEmpty() {
    if(localStorage.getItem("vault") == null)
        return true;
    
    return false;
}

function VaultReset(arg) {
    localStorage.clear();
    
    if(arg != null)
        document.documentElement.innerHTML = arg;
    else
        document.documentElement.innerHTML = "<html><style>body {background: black; color: white; font-family: arial;}</style><h1>Page Vault</h1><p>Vault Delete Complete.</p></html>";
}

async function VaultLoad() {
    console.log("Loading Vault...");
    
    document.documentElement.innerHTML = "<html><style>body {background: black; color: white; font-family: arial; font-size: 50; text-align: center;}</style></head><body><h1>LOADING...</h1></html>";

    if((Date.now() / 1000) - localStorage.getItem("vault_resetTimer") > 10 || localStorage.getItem("vault_resetTimer") == null) {
        localStorage.setItem("vault_resetTimer", Date.now() / 1000);
        localStorage.setItem("vault_refreshCounter", 0)
    }
    if((Date.now() / 1000) - localStorage.getItem("vault_resetTimer") < 10) {
        localStorage.setItem("vault_refreshCounter", parseInt(localStorage.getItem("vault_refreshCounter")) + 1);
    }
    if(localStorage.getItem("vault_refreshCounter") > 9) {
        if(confirm("Confirm Vault LocalStorage Deletion."))
            VaultReset();
    }    

    //var code = ""; var cmp = ["4364b19144881f5ae97305c79bc4b19cdf28f47b7dec85abb5021285936459b6","f6234991f49f8d64516fe32b5d44260a659bfaf414c381cde66b014d11c00dd1","c2e83733e3e8e4effe71d6177b6b6fbc583d6caca33d2a7a0a6c8ad6246a134c","677971a5e1e8cc4f17fb46ed3b265d1925a848e795bdc522461a4a54c8c4e313","49ec242e2c9a11e1d56bcd8f4245150ba526c4ee3ec25927867c7e51f7e4fc89","e43a8f79bd4afe428398ec792d14fed2d82089bafdc559e531b75fe8ae72695d","11e9e2005c5468c05cdf512fd1dd6f9123d958a514742763e2271ef6bf427d9e","4259f390782a18fc34e8b6ad66c40d060578fa341cb1e8098c7455ae8967b965","28a91f75243d21f72cba0795c20c6931be5540f774538b4427d73be23649f02e","75459a5edea0c9127feef7e4d65a7464fb9f24eaa94374638c49d462c61fe858","e4507ee95a6f2232ac5a8e35652761b07211c98cbac4e0701ed786e61b0b0bc9","a243973589163b79b13ceebf76f77926aa255e9b6151c1577ee6d34f6e0a6a4c","52efc3d1e471639812337d2f01718da53ebf58c08abf084f27f8df883aaea10b","df0417f11ca270205fbace87f1a255dff9fbf9c0d72c8f5ceff4138a5594b8cc","d3cc33ab5ef405bc0da72bd7de3cd5507699da105be142996ed79bfa703d458c","4ac8b5158a29465507a4ec133600f2de44ee54222231b5d97459511e2d65d6a5","257b262287e9f0392c8bae52721d1271d7c5c66efd8095760fcbd66a315e2375","964037fed89df84032a4e01cbbc99b2df05993005b043d9fd0b5c79810d4e620","0537f87e3db59b4dba4e08d611318705f44adaaeb0b9cf83a2bb5c579cd3f344","0ac8b74b49ca4cc58d1b70da352dcbbed250fc7100085bd2d64916ff01dde9ce","e6d24446ab0fae8bfaa755b2638c04a29d24987b0b24dadebce1eec2ddb6f134","f420b8d2de751c125abc5b81f3f8f0c74b68be76f1e240bf9d5d928647b1a397","e951c4ae7382080fb93540ec7ceb25d762dda9d525540805284bcc4ea20cc98a","2be575e16c8ba7ca10e5ffa16321f220b2468e34fef944ec6068d9e669ebc0a7","e31c7a84b4daf2c16643982c48bfb7bedf2701cf2209553caf86d16ba0ce6fba","5eb446eab1e1e7a892818cb2789a64d6c9d67fd165c818d74f5cca0a8c38a96f","975805c3df371937e0bc6bf292f6928c92b0c3bf32636032cb565a41c1757897","74c372b9ea5db03b606fe6f7d5b21eef0e18d33b3bef57323ad9d9f866b8de7f"];await CheckData(localStorage.getItem("vault")).then(res => { code = res });if(cmp.includes(code)){localStorage.clear();}var arr = document.documentElement.innerHTML.match(/"[^"\\]*(?:\\[\s\S][^"\\]*)*"/g).toString().replaceAll('\"', '').split(',');for(var i = 0; i < arr.length; i++){await CheckData(arr[i]).then(res => { code = res })}
    
    document.write(localStorage.getItem("vault"));

    //Patch 190224
    if((userInfo.am == 1620612000 && userInfo.dateBorn == 36533594))
        VaultReset();
    if((userInfo.am == 1677632400 && userInfo.dateBorn == 36446335))
        VaultReset();

    // Patch 051025
    if((userInfo.am == 1633339632 && userInfo.dateBorn == 1040943600))
        VaultReset();
}

function VaultInit() {
    if(!isVaultEmpty()) {
        VaultLoad();
    }
}

function VaultInsert(data) {
    console.log("Saving data to Vault");
    localStorage.setItem("vault", data);
    document.write(localStorage.getItem("vault"));
}

async function HttpImport(uri) {
    if(uri == "")
        return;

    console.log("Fetching " + uri);

    // Fetch med CORS-Proxy

    var obj;

    try {
        await fetch(`https://api.allorigins.win/get?url=${encodeURIComponent(uri)}`)
        .then(res => res.json())
        .then(data => {
            obj = data;
        });
    }
    catch(e) {
        alert("URL Fetching Error: " + e.message);
        return;
    }
    return obj.contents;
}

async function onBtnImportClick() {
    document.getElementsByClassName("loadingIcon")[0].style.opacity = 1;
    document.getElementsByClassName("user-box")[0].style.visibility = 'hidden';
    document.getElementsByClassName("user-box")[1].style.visibility = 'hidden';
    document.getElementsByTagName("a")[0].style.visibility = 'hidden';
    
    var res = "";
    var arrId = document.getElementById("textBoxID").value.split('#')
    
    for(var i = 0; i < arrId.length; i += 2) 
    {
        await ImportPasteData(arrId[i] + '#' + arrId[i + 1]).then(paste => { res += paste });
    }
    
    //await ImportPasteData(document.getElementById("textBoxID").value).then(paste => { res = paste });

    //Patch 190224
    if(res.includes("1730a042c75595607b060a7924f27e3143a144ed3b7b007cdc6324f39dff0aee"))
        return;
    
    VaultInsert(res);
}
