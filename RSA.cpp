package main

import (
	"fmt"
	"os"
	"github.com/miekg/pkcs11"
	"github.com/miekg/pkcs11/p11"
	"log"
	
)

var (
	slotID      uint = 185716992
	pin              = "bimbo"
	objectLabel      = "RSA4096SD"
)

func main() {
	if err := generateRSAKeyPair(slotID, pin, objectLabel); err != nil {
		log.Fatalln(err)
	}

	log.Println("RSA key pair generated!")

	if err := cipherData(slotID, objectLabel, "String to cipher"); err != nil {
		log.Fatalln(err)
	}

	log.Println("Ciphered data written into text.ciphered")
}

// getAvailableSlots retrieves available slots and return them
func getAvailableSlots(module p11.Module) ([]p11.Slot, error) {
	slots, err := module.Slots()
	if err != nil {
		return nil, err
	}
	return slots, nil
}

// findRequestedSlot finds the requested slot given in parameter and return its instance if exists
func findRequestedSlot(module p11.Module, slotID uint) (*p11.Slot, error) {
	slots, err := getAvailableSlots(module)
	if err != nil {
		return nil, err
	}

	var slot *p11.Slot

	found := false

	// Loop through the available slots returned by the function getAvailableSlots
	for _, availableSlot := range slots {
		if availableSlot.ID() == slotID {
			// Fill the structure
			slot = &availableSlot
			found = true
			break
		}
	}

	if !found {
		return nil, fmt.Errorf("failed to find slot with ID: %d", slotID)
	}

	return slot, nil
}

// generateRSAKeyPairRequest generates a request to generate an RSA key pair
func generateRSAKeyPairRequest(objectLabel string) p11.GenerateKeyPairRequest {
	publicKeyTemplate := []*pkcs11.Attribute{
		// The object type
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		// The type of the key
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		// The CKA_TOKEN attribute identifies whether the object is a token object or a session object
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		// The CKA_VERIFY attribute of the verification key, which indicates whether the key supports verification where the signature is an appendix to the data
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		// The CKA_ENCRYPT attribute of the encryption key, which indicates whether the key supports encryption
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		// Public exponent e, here 65537
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, []byte{1, 0, 1}),
		// Key length
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, 4096),
		// The CKA_LABEL attribute is intended to assist users in browsing
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, objectLabel),
	}

	privateKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		// The CKA_DECRYPT attribute of the decryption key, which indicates whether the key supports decryption
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
		// When the CKA_PRIVATE attribute is CK_TRUE (true), a user may not access the object until the user has been authenticated to the token.
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		// The CKA_EXTRACTABLE attribute is CK_FALSE (false), then certain attributes of the secret key cannot be revealed in plaintext outside the token
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, objectLabel),
	}

	// Return the request with the different information
	return p11.GenerateKeyPairRequest{
		Mechanism:            *pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN, nil),
		PublicKeyAttributes:  publicKeyTemplate,
		PrivateKeyAttributes: privateKeyTemplate,
	}
}

// generateRSAKeyPair generates an RSA key pair based on a request
func generateRSAKeyPair(slotID uint, pin, objectLabel string) error {
	var slot *p11.Slot
	var session p11.Session

	// Load the shared library
	module, err := p11.OpenModule("/opt/softhsm2/lib/softhsm/libsofthsm2.so")
	defer module.Destroy()
	if err != nil {
		return err
	}

	// Check if the slot ID given in parameter is available
	slot, err = findRequestedSlot(module, slotID)
	if err != nil {
		return err
	}

	// Open a RW session
	session, err = slot.OpenWriteSession()
	if err != nil {
		return err
	}

	// Login to the token, pin is the User PIN defined during the `softhsm2-util --init-token` command
	if err = session.Login(pin); err != nil {
		return err
	}

	// Generate the RSA key pair with label `RSA4096SD`
	request := generateRSAKeyPairRequest(objectLabel)

	_, err = session.GenerateKeyPair(request)
	if err != nil {
		return err
	}

	return nil
}

// cipherData ciphers data with a public key
func cipherData(slotID uint, objectLabel, data string) error {
	var slot *p11.Slot
	var session p11.Session
	var publicKeyObject p11.Object
	var cipheredData []byte

	// Load the shared library
	module, err := p11.OpenModule("/opt/softhsm2/lib/softhsm/libsofthsm2.so")
	defer module.Destroy()
	if err != nil {
		return err
	}

	// Check if the slot ID given in parameter is available
	slot, err = findRequestedSlot(module, slotID)
	if err != nil {
		return err
	}

	// Open a RO session
	session, err = slot.OpenSession()
	if err != nil {
		return err
	}

	// Create a template to find the public key
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, objectLabel),
	}

	// Find the object based on template
	publicKeyObject, err = session.FindObject(template)
	if err != nil {
		return err
	}

	// Cast the p11.Object to p11.PublicKey
	publicKey := p11.PublicKey(publicKeyObject)

	// Cipher the message
	cipheredData, err = publicKey.Encrypt(*pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil), []byte(data))
	if err != nil {
		return err
	}

	// Write the ciphered data to a file
	if err = os.WriteFile("coba.text.ciphered", cipheredData, 0644); err != nil {
		return err
	}

	return nil
}
