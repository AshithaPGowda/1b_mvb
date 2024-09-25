import hashlib
from typing import List, Optional
from nacl.signing import SigningKey, VerifyKey

DIFFICULTY = 0x07FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF

"""
Please do not modify any of the signatures on the classes below so the
autograder can properly run your submission. You are free (and encouraged!) to
add additional data members as you implement these functions.
"""

class Output:
    """
    A transaction output.
    """

    def __init__(self, value: int, pub_key: str):
        self.value = value
        self.pub_key = pub_key

    # Serialize the output to bytes
    def to_bytes(self) -> bytes:
        return self.value.to_bytes(4, 'big', signed=False) + bytes.fromhex(self.pub_key)

class Input:
    """
    A transaction input. The number refers to the transaction number where the
    input was generated (see `Transaction.update_number()`).
    """

    def __init__(self, output: Output, number: str):
        self.output = output
        self.number = number

    # Serialize the output to bytes
    def to_bytes(self) -> bytes:
        return self.output.to_bytes() + bytes.fromhex(self.number)

class Transaction:
    """
    A transaction in a block. A signature is the hex-encoded string that
    represents the bytes of the signature.
    """

    def __init__(self, inputs: List[Input], outputs: List[Output], sig_hex: str):
        self.inputs = inputs
        self.outputs = outputs
        self.sig_hex = sig_hex

        self.update_number()

    # Set the transaction number to be SHA256 of self.to_bytes().
    
    def update_number(self):
        tx_hash = hashlib.sha256(bytes.fromhex(self.to_bytes())).hexdigest()
        # Store this as the transaction number
        self.number = tx_hash
        


    # Get the bytes of the transaction before signatures; signers need to sign
    # this value!
    def bytes_to_sign(self) -> str:
        m = b''

        for i in self.inputs:
            m += i.to_bytes()
        
        for o in self.outputs:
            m += o.to_bytes()
        return m.hex()
    
    def to_bytes(self) -> str:
        m = b''

        for i in self.inputs:
            m += i.to_bytes()
        
        for o in self.outputs:
            m += o.to_bytes()

        m += bytes.fromhex(self.sig_hex)

        return m.hex()
    
class Block:
    """
    A block on a blockchain. Prev is a string that contains the hex-encoded hash
    of the previous block.
    """

    def __init__(self, prev: str, tx: Transaction, nonce: Optional[str]):
        self.tx = tx
        self.nonce = nonce
        self.prev = prev
        self.pow = None

    # Find a valid nonce such that the hash below is less than the DIFFICULTY
    # constant. Record the nonce as a hex-encoded string (bytearray.hex(), see
    # Transaction.to_bytes() for an example).
    def mine(self):
        nonce = 0
        while True:
            self.nonce = f'{nonce:064x}'  # Hexadecimal string with leading zeros
            block_hash = int(self.hash(), 16)  # Convert the hash to an integer
            
            if block_hash < DIFFICULTY:
                self.pow = self.hash()
                print("pow after finding difficulty: ",block_hash, "and ", self.pow)
                break  # Valid nonce found
            
            nonce += 1

    
    # Hash the block.
    def hash(self) -> str:
        m = hashlib.sha256()

        m.update(bytes.fromhex(self.prev))
        m.update(bytes.fromhex(self.tx.to_bytes()))
        if self.nonce is not None:
            m.update(bytes.fromhex(self.nonce))  # Add nonce (if present)

        return m.hexdigest()
    
class Blockchain:
    """
    A blockchain. This class is provided for convenience only; the autograder
    will not call this class.
    """
    
    def __init__(self, chain: List[Block], utxos: List[str]):
        self.chain = chain
        self.utxos = utxos
    
    def append(self, block: Block) -> bool:
        self.chain.append(block)
        self.utxos.append(block.tx.outputs)
        return True  

class Node:
    """
    All chains that the node is currently aware of.
    """
    def __init__(self):
        # We will not access this field, you are free change it if needed.
        self.chains = []
        self.chain = Blockchain([],[])

    # Create a new chain with the given genesis block. The autograder will give
    # you the genesis block.
    def new_chain(self, genesis: Block):
        self.chains.append([genesis]) 

    # Attempt to append a block broadcast on the network; return true if it is
    # possible to add (e.g. could be a fork). Return false otherwise.
    def append(self, block: Block) -> bool:
        found_valid_prev = False

        # Iterate over all the chains tracked by the node
        for chain in self.chains:
            # Check if the block's `prev` hash matches the last block in the chain (valid extension)
            if block.prev == chain[-1].hash():
                # Verify proof-of-work (POW) by checking the block hash vs. DIFFICULTY
                if int(block.hash(), 16) < DIFFICULTY:
                    # Append the block to this chain (valid continuation)
                    chain.append(block)
                    return True  # Successfully added the block to the chain
            # Check if the `prev` hash exists somewhere else in the chain (potential fork)
            for blk in chain:
                if block.prev == blk.hash():
                    found_valid_prev = True

        # If the `prev` hash exists somewhere in a chain, create a new fork (valid fork)
        if found_valid_prev:
            new_chain = [block]
            self.chains.append(new_chain)
            return True  # Added the block as a new fork
        
        # If no matching `prev` hash was found in any chain, the block is invalid
        return False

    # Build a block on the longest chain you are currently tracking. If the
    # transaction is invalid (e.g. double spend), return None.
    # Build a block on the longest chain you are currently tracking.
    def build_block(self, tx: Transaction) -> Optional[Block]:
        longest_chain = max(self.chains, key=len)
        prev_block_hash = longest_chain[-1].hash()

        # Verify the transaction before building a block
        if not verify_transaction(tx):
            print("Veriffy transaction failed, returning none")
            return None
        if not self.verify_utxos(tx):
            print("Veriffy UTXO failed, returning none")
            return None  # Reject double-spend transaction

        new_block = Block(prev_block_hash, tx, None)
        new_block.mine()
        longest_chain.append(new_block)

        # Update UTXO set (spend inputs, add outputs)
        self.update_utxos(tx)
        
        return new_block
    
    def verify_utxos(self, tx: Transaction) -> bool:
        # Check if the inputs in the transaction are unspent (UTXOs)
        for tx_input in tx.inputs:
            if tx_input.number not in self.chain.utxos:
                return False  # If input has already been spent, it's a double spend
        return True
    
    def update_utxos(self, tx: Transaction):
        # Remove spent inputs from UTXO set
        for tx_input in tx.inputs:
            self.chain.utxos.remove(tx_input.number)
        
        # Add new outputs to UTXO set
        for i, output in enumerate(tx.outputs):
            self.chain.utxos.append(tx.number + str(i))  # Unique identifier for UTXO

# Verify that a transaction's signature is valid using the associated public key
def verify_transaction(tx: Transaction) -> bool:
    for tx_input in tx.inputs:
        # Get the public key from the output
        pub_key = tx_input.output.pub_key
        verify_key = VerifyKey(bytes.fromhex(pub_key))
        print("In verify transaction, verify_key: ",verify_key,"pub_key :",pub_key)

        try:
            # Verify the signature on the transaction
            verify_key.verify(bytes.fromhex(tx.bytes_to_sign()), bytes.fromhex(tx.sig_hex))
        except Exception as e:
            print("Execption received: ",e)
            return False  # Verification failed
    return True

# Build and sign a transaction with the given inputs and outputs. If it is
# impossible to build a valid transaction given the inputs and outputs, you
# should return None. Do not verify that the inputs are unspent.
def build_transaction(inputs: List[Input], outputs: List[Output], signing_key: SigningKey) -> Optional[Transaction]:
    #each number in the input exists as a transaction already on the blockchain
    input_sum = sum(i.output.value for i in inputs)
    output_sum = sum(o.value for o in outputs)
     
    # Ensure inputs = outputs 
    if ((input_sum==0) | (output_sum==0)) :
        return None
    if input_sum != output_sum:
        return None
    temp=inputs[0].output.pub_key   
    # verify_key = VerifyKey(bytes.fromhex(inputs[0].output.pub_key) )
    # print(verify_key.verify(bytes.fromhex(inputs[0].number)))
    list=[]
    for i in inputs:
        
        if temp!=i.output.pub_key:
            return None
        if i.number in list:
            return None
        list.append(i.number)
        print(i.number,"i.number")
        print (i.output.value,", i.output.value")
        print (i.output.pub_key,", i.output.pubkey")
    
    
    
    # Create the transaction without a signature
    transaction = Transaction(inputs, outputs, "")
    
    # Sign the transaction's bytes_to_sign
    sig = signing_key.sign(bytes.fromhex(transaction.bytes_to_sign()))
    verify_key = VerifyKey(bytes.fromhex(inputs[0].output.pub_key))
    try:
        verify_key.verify(sig.message,sig.signature)
    except Exception:
        return None               
    transaction.sig_hex = sig.signature.hex()  # Add the signature in hex
    transaction.update_number()
    return transaction
