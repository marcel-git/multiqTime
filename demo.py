import random
alphabet = 's'*16+'S'*16
rand_string = ''.join(random.choice(alphabet) for _ in range(32)) + 'Pp'
print(rand_string)