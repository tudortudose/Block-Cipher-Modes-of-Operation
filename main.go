package main

import (
	"encoding/hex"
	"errors"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

func main() {
	a := app.New()
	w := a.NewWindow("AES - Modes of Operation")
	w.Resize(fyne.NewSize(600, 400))

	algorithmSelect := widget.NewSelect([]string{"AES-ECB", "AES-CBC", "AES-CFB", "AES-OFB", "AES-PCBC", "AES-CTR", "AES-GCM"}, nil)
	algorithmSelect.PlaceHolder = "Select Algorithm"

	keyEntry := widget.NewEntry()
	keyEntry.SetText("1234567890987654")
	keyEntry.SetPlaceHolder("Enter 16-byte Key (AES-128)")

	plaintextEntry := widget.NewMultiLineEntry()
	plaintextEntry.SetText("hi, this is a test text")
	plaintextEntry.SetPlaceHolder("Enter Plaintext")

	ciphertextEntry := widget.NewMultiLineEntry()
	ciphertextEntry.SetPlaceHolder("Ciphertext will appear here")

	decryptedTextEntry := widget.NewMultiLineEntry()
	decryptedTextEntry.SetPlaceHolder("Decrypted text will appear here")

	encryptButton := widget.NewButton("Encrypt", func() {
		algorithm := algorithmSelect.Selected
		key := []byte(keyEntry.Text)
		plaintext := []byte(plaintextEntry.Text)

		if len(key) != 16 {
			dialog.ShowError(errors.New("key must be 16 bytes long"), w)
			return
		}

		var ciphertext, nonce, tag []byte
		var iv []byte
		var err error
		switch algorithm {
		case "AES-ECB":
			ciphertext, err = encryptECB(plaintext, key)
		case "AES-CBC":
			ciphertext, iv, err = encryptCBC(plaintext, key)
		case "AES-CFB":
			ciphertext, iv, err = encryptCFB(plaintext, key)
		case "AES-OFB":
			ciphertext, iv, err = encryptOFB(plaintext, key)
		case "AES-PCBC":
			ciphertext, iv, err = encryptPCBC(plaintext, key)
		case "AES-CTR":
			ciphertext, iv, err = encryptCTR(plaintext, key)
		case "AES-GCM":
			ciphertext, nonce, tag, err = encryptGCM(plaintext, key)
		default:
			dialog.ShowError(errors.New("please select an algorithm"), w)
			return
		}

		if err != nil {
			dialog.ShowError(err, w)
			return
		}

		ciphertextEntry.SetText(hex.EncodeToString(ciphertext))

		if algorithm == "AES-GCM" {
			nonceHex := hex.EncodeToString(nonce)
			tagHex := hex.EncodeToString(tag)

			nonceDialog := dialog.NewCustom("Nonce and Tag", "Close", container.NewVBox(
				widget.NewLabel("Nonce: "+nonceHex),
				widget.NewLabel("Tag: "+tagHex),
				widget.NewButtonWithIcon("", theme.ContentCopyIcon(), func() {
					fyne.CurrentApp().Driver().AllWindows()[0].Clipboard().SetContent(nonceHex + "\n" + tagHex)
					dialog.ShowInformation("Copied", "Nonce and tag have been copied to clipboard.", w)
				}),
			), w)

			nonceDialog.Show()
		} else if algorithm == "AES-CBC" || algorithm == "AES-CFB" ||
			algorithm == "AES-OFB" || algorithm == "AES-PCBC" || algorithm == "AES-CTR" {
			ivHex := hex.EncodeToString(iv)
			ivDialog := dialog.NewCustom("Initialization Vector (IV)", "Close", container.NewHBox(
				widget.NewLabel(ivHex),
				widget.NewButtonWithIcon("", theme.ContentCopyIcon(), func() {
					fyne.CurrentApp().Driver().AllWindows()[0].Clipboard().SetContent(ivHex)
					dialog.ShowInformation("Copied", "IV has been copied to clipboard.", w)
				}),
			), w)
			ivDialog.Show()
		}
	})

	decryptButton := widget.NewButton("Decrypt", func() {
		algorithm := algorithmSelect.Selected
		key := []byte(keyEntry.Text)
		ciphertext, err := hex.DecodeString(ciphertextEntry.Text)

		if err != nil {
			dialog.ShowError(errors.New("invalid ciphertext format (must be hex)"), w)
			return
		}

		if len(key) != 16 {
			dialog.ShowError(errors.New("key must be 16 bytes long"), w)
			return
		}

		switch algorithm {
		case "AES-ECB":
			plaintext, err := decryptECB(ciphertext, key)
			if err != nil {
				dialog.ShowError(err, w)
				return
			}
			decryptedTextEntry.SetText(string(plaintext))
		case "AES-CBC", "AES-CFB", "AES-OFB", "AES-PCBC", "AES-CTR":
			ivEntry := widget.NewEntry()
			ivEntry.SetPlaceHolder("Enter IV in hex format")

			diag := dialog.NewForm("Enter IV", "Decrypt", "Cancel", []*widget.FormItem{
				widget.NewFormItem("IV", ivEntry),
			}, func(confirm bool) {
				if !confirm {
					return
				}

				iv, err := hex.DecodeString(ivEntry.Text)
				if err != nil {
					dialog.ShowError(errors.New("invalid IV format (must be hex)"), w)
					return
				}

				var plaintext []byte
				switch algorithm {
				case "AES-CBC":
					plaintext, err = decryptCBC(ciphertext, key, iv)
				case "AES-CFB":
					plaintext, err = decryptCFB(ciphertext, key, iv)
				case "AES-OFB":
					plaintext, err = decryptOFB(ciphertext, key, iv)
				case "AES-PCBC":
					plaintext, err = decryptPCBC(ciphertext, key, iv)
				case "AES-CTR":
					plaintext, err = decryptCTR(ciphertext, key, iv)
				}

				if err != nil {
					dialog.ShowError(err, w)
					return
				}
				decryptedTextEntry.SetText(string(plaintext))
			}, w)

			diag.Resize(fyne.NewSize(350, 100))
			diag.Show()
		case "AES-GCM":
			nonceEntry := widget.NewEntry()
			tagEntry := widget.NewEntry()
			nonceEntry.SetPlaceHolder("Enter Nonce in hex format")
			tagEntry.SetPlaceHolder("Enter Tag in hex format")

			diag := dialog.NewForm("Enter Nonce and Tag", "Decrypt", "Cancel", []*widget.FormItem{
				widget.NewFormItem("Nonce", nonceEntry),
				widget.NewFormItem("Tag", tagEntry),
			}, func(confirm bool) {
				if !confirm {
					return
				}

				nonce, err := hex.DecodeString(nonceEntry.Text)
				if err != nil {
					dialog.ShowError(errors.New("invalid nonce format (must be hex)"), w)
					return
				}

				tag, err := hex.DecodeString(tagEntry.Text)
				if err != nil {
					dialog.ShowError(errors.New("invalid tag format (must be hex)"), w)
					return
				}

				plaintext, err := decryptGCM(ciphertext, key, nonce, tag)
				if err != nil {
					dialog.ShowError(err, w)
					return
				}
				decryptedTextEntry.SetText(string(plaintext))
			}, w)

			diag.Resize(fyne.NewSize(350, 150))
			diag.Show()
		default:
			dialog.ShowError(errors.New("please select an algorithm"), w)
		}
	})

	w.SetContent(container.NewVBox(
		algorithmSelect,
		keyEntry,
		plaintextEntry,
		encryptButton,
		ciphertextEntry,
		decryptButton,
		decryptedTextEntry,
	))

	w.ShowAndRun()
}
