#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2013 ecdsa@github
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from electrum.i18n import _
from electrum.mnemonic import Mnemonic
import electrum.old_mnemonic
from electrum.plugin import run_hook
from electrum.bitcoin import is_b58_address

from .util import *
from .qrtextedit import ShowQRTextEdit, ScanQRTextEdit
from .completion_text_edit import CompletionTextEdit


def seed_warning_msg(seed):
    return ''.join([
        "<p>",
        _("Please save these {0} words on paper (order is important). "),
        _("This seed will allow you to recover your wallet in case "
          "of computer failure."),
        "</p>",
        "<b>" + _("WARNING") + ":</b>",
        "<ul>",
        "<li>" + _("Never disclose your seed.") + "</li>",
        "<li>" + _("Never type it on a website.") + "</li>",
        "<li>" + _("Do not store it electronically.") + "</li>",
        "</ul>"
    ]).format(len(seed.split()))

BTR_WALLET_MSG = ''.join([
    '<i>' + _('Please consider moving your BTR to a new wallet instead. ') + '</i>',
    _('If you decide to move your BTR to a new wallet, click BACK and select another wallet type.'),
    '<br />'])

class SeedLayout(QVBoxLayout):

    def seed_options(self):
        dialog = QDialog()
        vbox = QVBoxLayout(dialog)
        if 'ext' in self.options:
            cb_ext = QCheckBox(_('Extend this seed with custom words'))
            cb_ext.setChecked(self.is_ext)
            vbox.addWidget(cb_ext)
        if 'bip39' in self.options:
            def f(b):
                self.is_seed = (lambda x: bool(x)) if b else self.saved_is_seed
                self.is_bip39 = b
                self.on_edit()
                if b:
                    msg = ' '.join([
                        '<b>' + _('Notice') + ':</b>  ',
                        _('It is recommended to use Electrum seeds versus BIP 39 seeds.')
                    ])
                else:
                    msg = ''
                    self.seed_warning.setText(msg)

            cb_bip39 = QCheckBox(_('BIP39 seed'))
            cb_bip39.toggled.connect(f)
            cb_bip39.setChecked(self.is_bip39)
            vbox.addWidget(cb_bip39)
        vbox.addLayout(Buttons(OkButton(dialog)))
        if not dialog.exec_():
            return None
        self.is_ext = cb_ext.isChecked() if 'ext' in self.options else False
        self.is_bip39 = cb_bip39.isChecked() if 'bip39' in self.options else False

    def is_web_wallet_restore(self):
        return self.options and 'web_wallet_restore' in self.options

    def __init__(self, seed=None, title=None, icon=True, msg=None, options=None,
                 is_seed=None, passphrase=None, parent=None, for_seed_words=True):
        QVBoxLayout.__init__(self)
        self.parent = parent
        self.options = options
        if title:
            self.addWidget(WWLabel(title))
        if seed:  # "read only", we already have the text
            if for_seed_words:
                self.seed_e = ButtonsTextEdit()
            else:  # e.g. xpub
                self.seed_e = ShowQRTextEdit()
            self.seed_e.setReadOnly(True)
            self.seed_e.setText(seed)
        else:  # we expect user to enter text
            assert for_seed_words
            self.seed_e = CompletionTextEdit()
            self.seed_e.setTabChangesFocus(False)  # so that tab auto-completes
            self.is_seed = is_seed
            self.saved_is_seed = self.is_seed
            self.seed_e.textChanged.connect(self.on_edit)
            self.initialize_completer()

        self.seed_e.setMaximumHeight(75)
        hbox = QHBoxLayout()
        if icon:
            logo = QLabel()
            logo.setPixmap(QPixmap(":icons/seed.png").scaledToWidth(64, mode=Qt.SmoothTransformation))
            logo.setMaximumWidth(60)
            hbox.addWidget(logo)
        hbox.addWidget(self.seed_e)
        self.addLayout(hbox)
        hbox = QHBoxLayout()
        hbox.addStretch(1)
        self.seed_type_label = QLabel('')
        hbox.addWidget(self.seed_type_label)

        # options
        self.is_bip39 = False
        self.is_ext = False

        if options and not self.is_web_wallet_restore():
            opt_button = EnterButton(_('Options'), self.seed_options)
            hbox.addWidget(opt_button)
        
        if self.is_web_wallet_restore():
            self.is_bip39 = True
            self.is_ext = True
        self.addLayout(hbox)

        if passphrase:
            hbox = QHBoxLayout()
            passphrase_e = QLineEdit()
            passphrase_e.setText(passphrase)
            passphrase_e.setReadOnly(True)
            hbox.addWidget(QLabel(_("Your seed extension is") + ':'))
            hbox.addWidget(passphrase_e)
            self.addLayout(hbox)
        self.addStretch(1)

        if self.is_web_wallet_restore():
            self.seed_warning = WWLabel(BTR_WALLET_MSG)

            self.restore_vbox = QVBoxLayout()
            self.tx_vbox = QVBoxLayout()

            self.tx_vbox.addWidget(WWLabel(_('Transaction Password: ')))
            self.tx_line = QLineEdit()
            self.tx_line.setEchoMode(QLineEdit.Password)
            self.tx_vbox.addWidget(self.tx_line)
            self.restore_vbox.addLayout(self.tx_vbox)
            self.tx_line.textChanged.connect(self.enable_on_next_web_wallet)

            self.address_vbox = QVBoxLayout()
            self.address_vbox.addWidget(WWLabel(_('First Web Wallet Address: ')))
            self.first_address = QLineEdit()
            self.first_address.textChanged.connect(self.enable_on_next_web_wallet)
            self.address_vbox.addWidget(self.first_address)
            self.restore_vbox.addLayout(self.address_vbox)
            
            self.derivation_error_hbox = QHBoxLayout()
            self.derivation_error_hbox.addStretch(1)
        
            self.warning_tx_address = QLabel('')
            self.derivation_error_hbox.addWidget(self.warning_tx_address)
            
            self.restore_vbox.addLayout(self.derivation_error_hbox)
            self.addLayout(self.restore_vbox)
        else:
            self.seed_warning = WWLabel('')
        
        self.addWidget(self.seed_warning)


    def initialize_completer(self):
        english_list = Mnemonic('en').wordlist
        old_list = electrum.old_mnemonic.words
        self.wordlist = english_list + list(set(old_list) - set(english_list)) #concat both lists
        self.wordlist.sort()
        self.completer = QCompleter(self.wordlist)
        self.seed_e.set_completer(self.completer)

    def get_seed(self):
        text = self.seed_e.text()
        return ' '.join(text.split())

    def enable_on_next_web_wallet(self):
        self.parent.next_button.setEnabled(self.is_seed_test())

    def should_do_seed_test(self):
        if self.is_web_wallet_restore():
            tx_line = self.tx_line.text()
            first_address = self.first_address.text()
            is_address = is_b58_address(first_address)
            return len(self.get_seed()) > 0 and len(tx_line) > 0 and len(first_address) > 0 and is_address
        else:
            return True

    def is_seed_test(self):
        if self.is_web_wallet_restore():
            if self.should_do_seed_test():
                is_seed = self.is_seed(self.get_seed(), self.tx_line.text(), self.first_address.text())
            else:
                return False
            if not is_seed:
                self.warning_tx_address.setText('<b><font color="red">' + 
                _('Could not match first address with the seed and transaction password provided.') +
                '</font></b>'
                )
            else:
                self.warning_tx_address.setText('')
        else:
            is_seed = self.is_seed(self.get_seed())
        return is_seed

    def on_edit(self):
        from electrum.bitcoin import seed_type
        s = self.get_seed()
        is_good_seed = self.is_seed_test()
        if not self.is_bip39:
            t = seed_type(s)
            label = _('Seed Type') + ': ' + t if t else ''
        else:
            from electrum.keystore import bip39_is_checksum_valid
            is_checksum, is_wordlist = bip39_is_checksum_valid(s)
            status = ('checksum: ' + ('ok' if is_checksum else 'failed')) if is_wordlist else 'unknown wordlist'
            label = 'BIP39' + ' (%s)'%status
            if self.is_web_wallet_restore() and is_good_seed and is_wordlist:
                self.enable_on_next_web_wallet()
        self.seed_type_label.setText(label)

        if not self.is_web_wallet_restore():
            self.parent.next_button.setEnabled(is_good_seed)

        # to account for bip39 seeds
        for word in self.get_seed().split(" ")[:-1]:
            if word not in self.wordlist:
                self.seed_e.disable_suggestions()
                return
        self.seed_e.enable_suggestions()

class KeysLayout(QVBoxLayout):
    def __init__(self, parent=None, header_layout=None, is_valid=None, allow_multi=False):
        QVBoxLayout.__init__(self)
        self.parent = parent
        self.is_valid = is_valid
        self.text_e = ScanQRTextEdit(allow_multi=allow_multi)
        self.text_e.textChanged.connect(self.on_edit)
        if isinstance(header_layout, str):
            self.addWidget(WWLabel(header_layout))
        else:
            self.addLayout(header_layout)
        self.addWidget(self.text_e)

    def get_text(self):
        return self.text_e.text()

    def on_edit(self):
        b = self.is_valid(self.get_text())
        self.parent.next_button.setEnabled(b)


class SeedDialog(WindowModalDialog):

    def __init__(self, parent, seed, passphrase):
        WindowModalDialog.__init__(self, parent, ('Electrum-BTR - ' + _('Seed')))
        self.setMinimumWidth(400)
        vbox = QVBoxLayout(self)
        title =  _("Your wallet generation seed is:")
        slayout = SeedLayout(title=title, seed=seed, msg=True, passphrase=passphrase)
        vbox.addLayout(slayout)
        has_extension = True if passphrase else False
        run_hook('set_seed', seed, has_extension, slayout.seed_e)
        vbox.addLayout(Buttons(CloseButton(self)))
