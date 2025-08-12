### RAT Questions:

1. How does the Ceasar Cipher work?
    1. Shift each letter by a given amount.
    2. Substitute the letters defined by the key. 
    3. Depending on the key type, we either shift or substitute letters accordingly. 
    4. Change every *n*-th character, where *n* is defined by the key. 
2. What is the difference between a symmetric encryption scheme and an asymmetric encryption scheme?
    1. Symmetric uses one key to decrypt and encrypt, while asymmetric uses two keys: one to encrypt and one to decrypt.
    2. Symmetric encyption keys are *one-use-only*, like the *one-time-pad,* while asymmetric encryption keys can be used multiple times.
    3. Asymmetric encyption keys are *one-use-only*, like the *one-time-pad,* while symmetric encryption keys can be used multiple times.
    4. Symmetric keys can be used to encrypt all types of data, while asymmetric keys are limited to only communictation or data in transit.
3. What is a common challenge with symmetric cryptography?
    1. Distributing and exchanging keys.
    2. Generating keys.
    3. Deleting keys.
    4. Finding symmetric properties in keys. 
4. What is true about practical use of symmetric and asymmetric keys?
    1. They are often used together, where a symmetric key is shared using assymmetric cryptography.
    2. They are often used together, where an asymmetric key is shared using symmetric cryptography.
    3. Symmetric keys can be used in assymetric encryption shcemes, but asymmetric keys can not be used symmetric encryption schemes. 
    4. Asymmetric keys can be used in symmetric encryption shcemes, but symmetric keys can not be used asymmetric encryption schemes. 
5. What is true about hash functions?
    1. All of the mentioned.
    2. They act as a one-way trapdoor function. 
    3. Collisions can occur given that the output space is finite.
    4. Functions that have proven and known collisions should be deemed insecure.
6. Which property should a hash function $h$ exhibit?
    1. If $h(x) = y$, then $h(z) \neq y$.
    2. Given that $h(x) = y$, then $h(y) = x$.
    3. If $h(x) = y$, then $h(x+1) = y+1$.
    4. All of the mentioned.
7. What kind of encryption can the Diffie-Hellman Key Exchange be classified as? 
    1. Asymmetric.
    2. Symmetric.
    3. Substitution cipher.
    4. Permutation cipher.
8. What properties should a hash function $h$ exhibit?
    1. All of the mentioned.
    2. It should be fast, but not too fast. 
    3. It should be deterministic.
    4. The function described by $h$ should not have an inverse $h^{-1}$.
9. What best describes the *avalanche effect*? 
    1. A small change in the input of e.g. a hash function, should result in a completely different output. 
    2. By chaining multiple hash functions we increase the randonmess related to an input, making it harder to find the original input given an output. 
    3. The compromise of a symmetric key constitutes to a compromise for all instances that this key was used. 
    4. Cryptography built on the hardness assumption of the Discrete Logarithm Problem (DLP), such as Diffie-Hellman, will all break once we find efficient solutions for solving DLP. This will have an *avalanching* effect on the infrastrucutre our digital world is built upon. 
10. In the Diffie-Hellman key exchange…
    1. The generator $g$ can be reused in multiple key exchanges.  
    2. Alice and Bob end up with a different secret key, but the asymmetry of the key makes them able to decrypt eachother’s encrypted messages. 
    3. Only the party initiating the exchange will obtain the shared secret. 
    4. Anyone with access to the public keys being used can compute the shared secret.