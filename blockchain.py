
import hashlib
import binascii
import json
from time import time

from textwrap import dedent
from uuid import uuid4

from flask import Flask, jsonify, request, render_template
import requests

from urllib.parse import urlparse

import Crypto
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

class Blockchain(object):
  def __init__(self):
    self.chain = []
    self.current_transactions = []
    self.pending_transactions = set() #New set to track pending transaction hashes

    #creates the genesis block
    self.new_block(previous_hash=1, proof=100)
    self.nodes = set()
  def register_node(self, address):
    """
    Add a new node to the list of nodes
    :param address: <str> Address of node. Eg. 'http://192.168.0.5:5000'
    :return: None
    """

    parsed_url = urlparse(address)
    self.nodes.add(parsed_url.netloc)

  def valid_chain(self, chain):
    """
    Determine if a given blockchain is valid
    :param chain: <list> A blockchain
    :return: <bool> True if valid, False if not
    """

    last_block = chain[0]
    current_index = 1

    while current_index<len(chain):
      block = chain[current_index]
      print(f"{last_block}")
      print(f"{block}")
      print("\n-----------\n")

      #check the hash of the block is correct
      if block['previous_hash'] != self.hash(last_block):
        return False

      #check that proof of work is correct
      if not self.valid_proof(last_block['proof'], block['proof']):
        return False
      
      last_block = block
      current_index += 1

    return True
  
  def resolve_conflicts(self):
    """
    This is our Consensus Algorithm, it resolves conflicts
    by replacing our chain with the longest one in the network.
    :return: <bool> True if our chain was replaced, False if not
    """

    neighbors = self.nodes
    new_chain = None

    max_length = len(self.chain)

    for node in neighbors:
      response = requests.get(f'http://{node}/chain')

      if response.status_code == 200:
        length = response.json()['length']
        chain = response.json()['chain']


        #check if the length is longer and the chain is valid
        if length > max_length and self.valid_chain(chain):
          max_length = length
          new_chain = chain

    if new_chain:
      self.chain = new_chain
      return True
  
    return False



  def proof_of_work(self,last_proof):
    """
      Simple Proof of Work Algorithm:
        - Find a number p' such that hash(pp') contains leading 4 zeroes, where p is the previous p'
        - p is the previous proof, and p' is the new proof
      :param last_proof: <int>
      :return: <int>
    """

    proof = 0
    while self.valid_proof(last_proof, proof) is False:
      proof +=1

    return proof
  
  @staticmethod
  def valid_proof(last_proof, proof):
    guess = f'{last_proof}{proof}'.encode()
    guess_hash = hashlib.sha256(guess).hexdigest()
    return guess_hash[:4] == "0000"
    
  def new_block(self, proof, previous_hash=None):
    """
    Create a new Block in the Blockchain
    :param proof: <int> The proof given by the Proof of Work algorithm
    :param previous_hash: (Optional) <str> Hash of previous Block
    :return: <dict> New Block
    """
    block = {
      "index": len(self.chain) + 1,
      "timestamp": time(),
      "transactions": self.current_transactions.copy(),  # Use a copy of the transactions
      "proof": proof,
      "previous_hash": previous_hash or self.hash(self.chain[-1]),
    }
        
    # Reset current list of transactions
    self.current_transactions = []
    self.pending_transactions.clear()

    self.chain.append(block)
    return block


  def broadcast_transaction(self, sender_pk, recipient_pk, amount):
    transaction = {
      "sender": sender_pk,
      "recipient": recipient_pk,
      "amount": amount,
      "broadcast": True
    }
    for node in self.nodes:
      response = requests.post(f'http://{node}/transactions/new', json=transaction)
      if response.status_code != 201:
        return False
    return True
  

  def new_transaction(self, sender_pk, recipient_pk, amount, broadcast=False, mining=False):
    
    """
    Creates a new transaction to go into the next mined Block
    :param sender: <str> Address of the Sender
    :param recipient: <str> Address of the Recipient
    :param amount: <int> Amount
    :return: <int> The index of the Block that will hold this transaction
    """
    transaction = {
      'sender': sender_pk,
      'recipient': recipient_pk,
      'amount': amount,
    }

    transaction_hash = self.hash(transaction)

    if transaction_hash not in self.pending_transactions:
      self.current_transactions.append(transaction)
      self.pending_transactions.add(transaction_hash)
    
      if(not mining and not broadcast): 
        print(self.nodes)
        self.broadcast_transaction(sender_pk, recipient_pk, amount)
    return self.last_block['index'] + 1
  
  def verify_key_pair(self, sender_sk, sender_pk):
    try:
      # Convert hex strings back to bytes
      sender_sk = binascii.unhexlify(sender_sk)
      sender_pk = binascii.unhexlify(sender_pk)

      # Import the private and public keys
      priv_key = RSA.import_key(sender_sk)
      pub_key = RSA.import_key(sender_pk)
      
      # Create a message to sign
      message = b"Test message for key verification"
      
      # Create a hash of the message
      hash_obj = SHA256.new(message)
      
      # Sign the hash with the private key
      signature = pkcs1_15.new(priv_key).sign(hash_obj)
      
      # Verify the signature using the public key
      pkcs1_15.new(pub_key).verify(hash_obj, signature)
      
      return True
    except (ValueError, TypeError):
      # print("not key pair")
      return False

  @staticmethod
  def hash(data):
    """
    Creates a SHA-256 hash of a Block
    :param block: <dict> Block
    :return: <str>
    """

    #We must make sure that the dictionary is Ordered, or we'll have inconsistent hashes
    data_string = json.dumps(data, sort_keys=True).encode()
    return hashlib.sha256(data_string).hexdigest()

  @property
  def last_block(self):
    return self.chain[-1]
  


app = Flask(__name__)

# Generate a globally unique address for this node
node_identifier = str(uuid4()).replace('-', '')

#insantiate the Blockchain
blockchain = Blockchain()

@app.route('/mine', methods=['GET'])
def mine():
  # We run the proof of work algorithm to get the next proof...
  last_block = blockchain.last_block
  last_proof = last_block['proof']
  proof = blockchain.proof_of_work(last_proof)

  # We must receive a reward for finding the proof.
  # The sender is "0" to signify that this node has mined a new coin.
  blockchain.new_transaction(
    sender_pk="0",
    recipient_pk=node_identifier,
    amount=1,
    mining=True
  )

  # Forge the new Block by adding it to the chain
  previous_hash = blockchain.hash(last_block)
  block = blockchain.new_block(proof, previous_hash)

  response = {
    'message': "New Block Forged",
    'index': block['index'],
    'transactions': block['transactions'],
    'proof': block['proof'],
    'previous_hash': block['previous_hash'],
  }

  return jsonify(response), 200

@app.route('/mine_template', methods=['GET'])
def mine_template():
  return render_template('./mine_template.html')


@app.route('/transactions/new', methods=['POST'])
def new_transactions():
  values = request.get_json()

  #sender_pk: sender public key
  #sender_sk: sender private key ("sk" as in secret key)
  #recipient_pk: recipient public key
  required = ['sender_pk', 'sender_sk', 'recipient_pk', 'amount']
  if not all (k in values for k in required):
    return "Missing value", 400
  
  # print("hello there")
  if(blockchain.verify_key_pair(values['sender_sk'], values['sender_pk'])):
    #create a new Transaction
    if ('broadcast' not in values):
      index = blockchain.new_transaction(values['sender_pk'], values['recipient_pk'], values['amount'])
    else:
      index = blockchain.new_transaction(values['sender_pk'], values['recipient_pk'], values['amount'], broadcast=True)

    response = {'message': f'Transaction will be added to Block {index}'}
    return jsonify(response), 201
  else:
    response = {'Error': "Public key and Private key does not match."}
    return jsonify(response), 400
  
@app.route('/make/transaction')
def make_transaction():
  return render_template('./make_transaction.html')

@app.route('/chain', methods=['GET'])
def full_chain():
  response = {
    'chain': blockchain.chain,
    'length': len(blockchain.chain)
  }

  return jsonify(response), 200

@app.route("/pending", methods=['GET'])
def pending_transactions():
  response = {
    'pending': blockchain.current_transactions
  }
  return jsonify(response), 200

@app.route('/nodes/register', methods=['POST'])
def register_nodes():
  values = request.get_json()

  nodes = values.get('nodes')
  if nodes is None:
    return "Error: Please supply a valid list of nodes", 400
  
  for node in nodes:
    blockchain.register_node(node)

  response = {
    'message': 'New nodes have been added',
    'total_nodes': list(blockchain.nodes),
  }

  return jsonify(response), 201

@app.route('/configure', methods=['GET'])
def configure():
  return render_template("./configure.html")

@app.route('/nodes/resolve', methods=['GET'])
def consensus(): 
  replaced = blockchain.resolve_conflicts()

  if replaced:
    response = {
      'message': 'Our chain was replaced',
      'new_chain': blockchain.chain
    }
  else:
    response = {
      'message': 'Our chain is authoritative',
      'chain': blockchain.chain
    }
  
  return jsonify(response), 200

@app.route('/wallet/new', methods=['GET'])
def new_wallet():
  random_gen = Crypto.Random.new().read
  private_key = RSA.generate(1024, random_gen)
  public_key = private_key.public_key()

  response = {
    'private_key': binascii.hexlify(private_key.export_key(format='DER')).decode('ascii'),
    'public_key': binascii.hexlify(public_key.export_key(format='DER')).decode('ascii')
  }

  return jsonify(response), 200

@app.route('/view/transactions', methods=['GET'])
def view_transactions():
  return render_template("view_transactions.html")

@app.route('/', methods=['GET'])
def home_page():
  return render_template('./index.html')



if __name__ == "__main__":
  from argparse import ArgumentParser
  
  parser = ArgumentParser()
  parser.add_argument('-p', '--port', default=4000, type=int, help='port to listen on ')
  args = parser.parse_args()
  port = args.port

  app.run(host='127.0.0.1', port=port)
