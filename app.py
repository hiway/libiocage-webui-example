import asyncio
import os
import random
import ssl
import traceback

import click

from OpenSSL import crypto
from pathlib import Path

from makeweb import (
    Doc, CSS,
    head, meta, title, style, script,
    body, h3, form, _input, label,
    ul, li, a, img, textarea, div,
)
from quart import (
    Quart, request, url_for, abort
)

META = {
    'viewport': 'width=device-width, initial-scale=1',
}

app = Quart(__name__,
            static_folder=os.path.join(
                os.path.dirname(os.path.abspath(__file__)),
                'static'),
            static_url_path='/static',
            )

app.secret_key = os.getenv('SECRET_KEY', '2#76hsdv76r7e9f(e76f13%fr17ifr#1*re')

css = CSS()

css('*',
    font__family='Verdana', )
css('#loading',
    display='none',
    )
css('#exec_label',
    color='#888',
    display='none',
    )
css('#exec_input',
    font__size='1.6em',
    width='20em',
    max__width='100%',
    height='1.8em',
    padding='0',
    margin='0',
    )
css('#exec_submit',
    font__size='1.2em',
    padding='0.85em 0.5em 0.5em 0.5em',
    margin='0',
    border='0',
    )
css('li',
    padding__top='0.2em'
    )
css('#exec_form',
    text__align='center',
    padding='1em 1em',
    border__bottom='1px #d0d0d0 dashed',
    )
css('label',
    padding='1em 1em',
    )
css('textarea',
    height='100%',
    width='100%',
    border='none',
    )


def render_index(stdout: list = None):
    doc = Doc('html')
    with head():
        meta(charset='utf-8')
        [meta(**{k: v}) for k, v in META.items()]
        title('Libiocage-GUI')
        with style():
            css.embed()
        with form(id='exec_form',
                  title='Type a command to run in a jail.',
                  ic__post__to='/exec',
                  ic__target='#stdout',
                  ic__indicator='#loading',
                  ):
            label('Execute in one-shot jail:', _for='#command', id='exec_label')
            _input(id='exec_input', name='command', autofocus=True,
                   ic__indicator='#loading',
                   )
            _input(id='exec_submit', type='submit', value='exec')
            img(src=url_for('static', filename='images/loader.gif'),
                alt='loading...', id='loading')
    with body():
        with div(id='stdout'):
            if stdout:
                render_stdout(doc, stdout)
        script(src=url_for('static', filename='js/jquery-3.3.1.min.js'),
               type='text/javascript')
        script(src=url_for('static', filename='js/intercooler-1.2.1.min.js'),
               type='text/javascript')
    return str(doc)


def render_stdout(doc: Doc, stdout: list):
    textarea(stdout)
    return doc


@app.route('/', methods=['GET'])
async def index():
    data = await request.form
    command = data.get('command', '')
    if command:
        stdout = excute_command_in_jail(command)
    else:
        stdout = ''
    return render_index(stdout=stdout)


@app.route('/exec', methods=["POST"])
async def search_fragment():
    data = await request.form
    command = data.get('command', '')
    if command:
        stdout = excute_command_in_jail(command)
    else:
        stdout = []
    doc = Doc()
    render_stdout(doc, stdout)
    # intercooler.js interprets empty response and single space as no-op,
    # send two spaces to clear target if response would be empty.
    return str(doc) or '  '


def excute_command_in_jail(command):
    try:
        import iocage
    except ImportError:
        click.echo('Unable to import iocage (Try `pip install libiocage`?)')
        return 'Error: libiocage is not installed, or perhaps not running on FreeBSD?'

    stdout = ''
    jail = iocage.Jail(dict(
        name='one-shot',
        vnet=True,
        ip4_addr='vnet0|10.0.1.89/24',
        defaultrouter='10.0.1.1',
        interfaces='vnet0:bridge0',
    ), new=True)
    jail.create('11.2-RELEASE')
    try:
        stdout = jail.fork_exec(command)
    except Exception as e:
        click.echo(f'Exception when running command: {command!r}')
        stdout = traceback.format_exc()
        traceback.print_exc()
    finally:
        jail.stop(force=True)
        jail.destroy()
    return stdout


def ensure_certificate_and_key(cert_file_path, key_file_path):
    if os.path.isfile(cert_file_path) and os.path.isfile(key_file_path):
        return cert_file_path, key_file_path

    click.echo('Generating certificate and key.')

    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 2048)

    cert = crypto.X509()
    cert.get_subject().C = "IN"
    cert.get_subject().ST = "Local"
    cert.get_subject().L = "Local"
    cert.get_subject().O = "Libiocage-GUI"
    cert.get_subject().OU = "Libiocage-GUI"
    cert.get_subject().CN = 'localhost'
    cert.set_serial_number(random.randrange(999999))
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(10 * 365 * 24 * 60 * 60)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(k)
    cert.sign(k, 'sha256')

    with open(cert_file_path, "wt") as cert_file:
        cert_file.write(str(
            crypto.dump_certificate(
                crypto.FILETYPE_PEM, cert), 'utf-8'))

    with open(key_file_path, "wt") as key_file:
        key_file.write(str(
            crypto.dump_privatekey(
                crypto.FILETYPE_PEM, k), 'utf-8'))

    return cert_file_path, key_file_path


@click.group()
def main():
    pass


@main.command('run')
@click.option('--bind', default='localhost')
@click.option('--port', default='7153')
@click.option('--insecure', default=False, is_flag=True)
@click.option('--home', default='~/.config/iocage-gui/')
def run_server(bind, port, insecure, home):
    loop = asyncio.get_event_loop()
    if insecure:
        app.run(host=bind, port=port, loop=loop)
    else:
        DIR_PATH = os.path.expanduser(home)
        home = Path(DIR_PATH)
        home.mkdir(parents=True, exist_ok=True)
        CERT_PATH = os.path.join(DIR_PATH, 'ssl.cert')
        KEY_PATH = os.path.join(DIR_PATH, 'ssl.key')
        try:
            cert_file_path, key_file_path = ensure_certificate_and_key(
                CERT_PATH,
                KEY_PATH,
            )
        except OSError:
            click.echo('Unable to generate SSL certificate and key, '
                       'check permissions at path: {conf_dir}'.format(conf_dir=DIR_PATH))
            raise click.Abort()

        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_COMPRESSION
        ssl_context.set_ciphers('ECDHE+AESGCM')
        ssl_context.load_cert_chain(certfile=cert_file_path, keyfile=key_file_path)
        ssl_context.set_alpn_protocols(['h2', 'http/1.1'])
        app.run(host=bind, port=port, ssl=ssl_context, loop=loop)


if __name__ == '__main__':
    main()
