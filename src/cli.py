from typing import Annotated
from rich import print
from ca.certdb import CertDatabase, CERTDB_CONFIGFILE
import typer, sys

app = typer.Typer()
ca_commands = typer.Typer()
service_commands = typer.Typer()
app.add_typer(ca_commands, name="ca")
app.add_typer(service_commands, name="services")

@ca_commands.command("status")
def ca_status(config: Annotated[str, typer.Option(help="Authority configuration file (toml)")] = CERTDB_CONFIGFILE):
    try:
        db = CertDatabase(configfile=config)
        if db.authority == None: 
            print("[bold]Certificate Authority[/bold]")
            print("Status: [red]Not initiated[/red] :warning:")
        else:
            print(f"[bold]Certificate Authority [ [blue]{db.authority.common_name}[/blue] ] [/bold]")
            print(f"Path: {db.path}")
            print(f"Serial: {db.authority.sn}")
            print(f"Validity: up to {db.authority.crt.not_valid_after_utc}")
    except FileNotFoundError: 
        print(f"Configuration file not found ({config}) :warning:")


@ca_commands.command("get")
def ca_get(element: Annotated[str, typer.Option(help="Export some data like certificate, key, crl, chain")] = "certificate", config: Annotated[str, typer.Option(help="Authority configuration file (toml)")] = CERTDB_CONFIGFILE):
    try:
        db = CertDatabase(configfile=config)
        if db.authority == None: 
            print("Certificate Authority [red]Not initiated[/red] :warning:")
            return
        
        if element == "certificate":
            sys.stdout.write(db.authority.crt_data)
            return
    except FileNotFoundError: 
        print(f"Configuration file not found ({config}) :warning:")

@ca_commands.command("init")
def ca_init(config: Annotated[str, typer.Option(help="Authority configuration file (toml)")] = CERTDB_CONFIGFILE):
    db = CertDatabase(configfile=config)
    if db.authority == None: 
        auth = Certificate()
        auth.SetKeyPassphare(db.conf.get("Authority", "KeyPassphrase", default=None))
        auth.GenerateKey(KeyType.RSA4096)
        if db.conf.get("Authority", "Parent", default="self") == "self":
            auth.crt_type = CertType.RootCA
            auth.GenerateSelfSign(db.conf.get("Authority"), int(db.conf.get("Authority", "ExpireOffset", default=5844)), length=int(db.conf.get("Authority", "Length", default=0)))
        else:
            auth.crt_type = CertType.IntermediateCA
            csr = auth.GenerateRequest(db.conf.get("Authority"), length=int(db.conf.get("Authority", "Length", default=0)))
            req = requests.post(db.conf.get("Authority", "Parent") + "/api/pki/ca/request", json=csr.dict())
            if req.status_code == 200:
                res = requests.get(db.conf.get("Authority", "Parent") + "/api/pki/ca/sign?sn=" + str(auth.sn))
                if res.status_code == 200:
                    print(res.text)
                    auth.crt_data = res.text
                else:
                    raise Exception("Invalide return code durring CRT signing.")
            else:
                raise Exception("Invalide return code durring CSR submission.")
        auth.write(os.path.join(db.path, "Authority.json"))

@service_commands.command("generate")
def service_generate(config: Annotated[str, typer.Option(help="Authority configuration file (toml)")] = CERTDB_CONFIGFILE):
    db = CertDatabase(configfile=config)
    if db.authority == None: 
        print("Certificate Authority [red]Not initiated[/red] :warning:")
        return
    
    

if __name__ == "__main__":
    app()