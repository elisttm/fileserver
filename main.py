import quart, hypercorn, asyncio, os, re, shutil, dotenv, sqlite3, time, datetime, random, string, bcrypt
from quart import request, redirect, render_template, send_from_directory, url_for, abort, flash, jsonify
from quart_auth import AuthUser, current_user, login_required, login_user, logout_user, QuartAuth
from werkzeug.utils import secure_filename

dotenv.load_dotenv()

appdir = os.path.dirname(os.path.realpath(__file__))
uploads = appdir+"/uploads"

db = sqlite3.connect(f"{appdir}/data.db")
cur = db.cursor()
cur.execute("CREATE TABLE IF NOT EXISTS users (name TEXT NOT NULL UNIQUE, pass TEXT NOT NULL)")
cur.execute("CREATE TABLE IF NOT EXISTS keys (key TEXT NOT NULL UNIQUE)")

app = quart.Quart(__name__)
app.config["UPLOAD_FOLDER"] = uploads
app.config["SESSION_PERMANENT"] = True
app.config["MAX_CONTENT_LENGTH"] = 1024*1024*256 # 256mb (just in case the in-place checks fail)
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 60*60*12 # 12hr
app.config["QUART_AUTH_COOKIE_NAME"] = 'AUTH'
app.config["QUART_AUTH_COOKIE_SECURE"] = False
app.secret_key = os.environ["secret"]
QuartAuth(app)

user_admins = ("eli")
reset_codes = {}

abc123_regex = re.compile("([A-Za-z1-9])")
url_regex = re.compile("^(https?:\\/\\/)?(?:www\\.)?[-a-zA-Z0-9@:%._\\+~#=]{1,256}\\.[a-zA-Z0-9()]{1,6}\\b(?:[-a-zA-Z0-9()@:%_\\+.~#?&\\/=]*)$")

ext_regex = {
	"image":	"a?png|j(pe?g|fif|x(l|r))|gif|webp|bmp|tiff?|avif",
	"image1":	"svg|ico|cur|psd?|pdn|swf|art|dxf|dng|vtf",
	"sound":	"aac|mp3|m.?a|ogg|flac|wav|amr|aiff|mid",
	"video":	"mp4|webm|m.?v|mov|avi|wmv|mpg|flv|3gp",
	"document":	"rtf|e?pub|pdf|doc.?|pptx?|xlsx?|od(s|t|p)|eot|dcm|html?",
	"archive":	"t?.?z.{0,2}|.?ar|br|rpm|cab|deb|pak|n(es|64|ds|ro)|wad|pkg|vpk|vmf",
	"disk":		"iso|im(a|g|z)|dim|vhd|gpt|mbr|cue",
	"text":		"txt|ini|cfg|md",
	"script":	"(b|j)son|(ya?|to|x)ml|py|c(c|pp|ss?)?|js|net|php|ahk|vmt",
	"program":	"exe|msi|bat|sh|com|run",
	"binary":	"bin|dat"
}

for ext in ext_regex:
	ext_regex[ext] = re.compile(f"(?i)\\.({ext_regex[ext]})$")

class ff: # portable functions

	def file_type(file):
		file = file.lower()
		if "readme" in file:
			return "important"
		for ext in ext_regex:
			if re.search(ext_regex[ext], file):
				return ext
		return "generic"

	def dir_size(path):
		total_size = 0
		for dirpath, dirnames, filenames in os.walk(path):
			for f in filenames:
				fp = os.path.join(dirpath, f)
				if not os.path.islink(fp):
					total_size += os.path.getsize(fp)
		return total_size

	def byte_size(num):
		step = 1024.0
		if num == 0:
			return "--"
		for x in ['B', 'KB', 'MB', 'GB', 'TB']:
			if num < step:
				return "%3.1f %s" % (num, x)
			num /= step

	def parent_path(path):
		return "/".join(path.split("/")[:-1])

def sanitize_filename(filename):
	# truncates and sanitizes filenames while preserving extensions
	ext = os.path.splitext(filename)[1]
	length = 50-len(ext)
	filename = (filename[::-1].replace(ext[::-1],""[::-1], 1))[::-1]
	truncate = filename if len(filename) <= length else filename[:length]
	return secure_filename(truncate+ext)

def increment_filename(filename, targetpath):
	i = 0
	newfilename = filename
	while os.path.exists(f"{targetpath}/{newfilename}"):
		i += 1
		newfilename = f"{filename}_{i}"
	return newfilename

def get_filelist(path):
	# huge hideous nasty function
	if not os.path.exists(path):
		return {}
	files, folders, up_files, low_files = {}, {}, {}, {}
	split_path = path.split("/")
	parent = {split_path[-2]: {"type": "back",}} if split_path[-2] != "uploads" else {} # parent directory

	for file in os.listdir(path):
		filepath = f"{path}/{file}"
		try:
			stats = os.stat(filepath)
			if os.path.isdir(filepath):
				# folders.. obviously
				folders[str(file)] = {
					"type": "folder",
					"size": ff.dir_size(filepath),
				}
			elif file.startswith("LINKTO"):
				with open(filepath, 'r') as linkfile:
					lf = (linkfile.readlines())
					lflink = lf[0].strip() if (len(lf) >= 1 and lf[0].strip()) else None
					lfname = lf[1].strip()[:32] if (len(lf) >= 2 and lf[1].strip()) else lflink
				if not lflink:
					# invalid link syntax
					files[str(file)] = {
						"type": "broken",
					}
				elif os.path.exists(f"{uploads}{lflink}"):
					if os.path.isdir(f"{uploads}{lflink}"):
						# links to other folders on the site
						low_files[str(file)] = {
							"type": "linkfolder",
							"size": ff.dir_size(filepath),
							"link": lflink,
							"name": lfname,
						}
					else:
						# links to other files on the site
						stats = os.stat(filepath)
						low_files[str(file)] = {
							"type": "link",
							"size": stats.st_size,
							"date": datetime.datetime.fromtimestamp(stats.st_mtime).strftime("%D %I:%M %p") if stats.st_mtime else "--",
							"link": lflink,
							"name": lfname,
						}
				elif re.search(url_regex, lflink):
					# links to external urls
					low_files[str(file)] = {
						"type": "website",
						"link": lflink,
						"name": lfname,
				}
				else:
					# linked item doesnt exist
					files[str(file)] = {
						"type": "broken",
					}
			else:
				# regular normal files
				files[str(file)] = {
					"type": ff.file_type(file),
					"size": stats.st_size,
					"date": datetime.datetime.fromtimestamp(stats.st_mtime).strftime("%D %I:%M %p") if stats.st_mtime else "--",
				}
				# any file classified as important gets sorted to the top
				if files[file]["type"] == "important":
					up_files[file] = files.pop(file)
		except Exception as e:
			print(f"couldnt process file {file}: {e}")
		
	# sort files and folders case-ignorantly
	files = {k: files[k] for k in sorted(files.keys(), key=str.casefold)}
	folders = {k: folders[k] for k in sorted(folders.keys(), key=str.casefold)}

	return {**parent, **folders, **up_files, **low_files, **files}

def get_userdata(user):
	query = cur.execute(f"SELECT name FROM users WHERE name='{user}'").fetchone()
	if not query or not os.path.isdir(f"{uploads}/{user}"):
		return None
	userdir = f"{uploads}/{user}"
	return {
		"path": userdir,
		"usage": ff.dir_size(userdir),
		"storage": 2147483648, # 2gb (ignored for admins)
		"is_admin": True if user in user_admins else False,
	}

def user_exists(user):
	casefold_users = [u.casefold() for u in os.listdir(uploads)]
	if user.casefold() in casefold_users:
		return True
	return False

def generate_key(length=6):
    return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(length))

def hash_password(password):
	return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def check_password(user, input_password):
	query_password = cur.execute(f"SELECT pass FROM users WHERE name='{user}'").fetchone()
	if not query_password:
		return False
	return bool(bcrypt.checkpw(input_password.encode(), query_password[0].encode()))

async def log(request, txt):
	# for logging significant actions (mainly signups and uploads)
	# this method of parsing ips is really idiotic but i dont care
	if "CF-CONNECTING-IP" in request.headers:
		ip = request.headers["CF-CONNECTING-IP"] # cloudflare proxy
	elif "HTTP_X_REAL_IP" in request.headers:
		ip = request.headers["HTTP_X_REAL_IP"] # nginx
	elif "X-FORWARDED-FOR" in request.headers:
		ip = request.headers["X-FORWARDED-FOR"] # other proxies
	else:
		ip = request.headers["REMOTE-ADDR"] # no proxy
	log_msg = f"[{time.strftime('%X %x %Z')}] [{ip}] {txt}"
	print(log_msg)
	with open(f"{appdir}/log.txt", "a") as logfile:
		logfile.write(log_msg+"\n")


@app.route("/", defaults={"user": "public", "folder": ""})
@app.route("/u/", defaults={"user": "public", "folder": ""})
@app.route("/u/<user>", defaults={"folder": ""}, methods=["GET", "POST"])
@app.route("/u/<user>/<path:folder>", methods=["GET", "POST"])
async def _files(user, folder):
	fulldir = f"{uploads}/{user}" + (f"/{folder}" if folder else "")

	# file redirect for stupid dumb idiots who fabricate their own links...
	if not os.path.isdir(fulldir):
		if os.path.exists(fulldir):
			return redirect(url_for("_serve_files", user=user, filepath=folder))
		return abort(404)

	filelist = get_filelist(fulldir)
	userdata = get_userdata(user)

	manage = True if ("manage" in request.args and user == current_user.auth_id) else False

	if request.method == "POST" and user == current_user.auth_id:
		form = (await request.form)
		selections = form.getlist("select")

		if "RENAME" in form:
			casefold_files = [f.casefold() for f in filelist.keys()]
			for file in filelist:
				if filelist[file]["type"] == "back":
					continue
				formid = f"RENAME-{file}"
				if not form[formid] or form[formid] == "" or form[formid] == file:
					continue
				rename = sanitize_filename(form[formid])
				if rename.casefold() in casefold_files:
					await flash(f"{rename} already exists!")
					continue
				os.rename(f"{fulldir}/{file}", f"{fulldir}/{rename}")
				await flash(f"renamed {file} -> {rename}")
					
		elif "NEWFOLDER" in form:
			if len(folder.split("/")) >= 4:
				await flash("you have hit the folder depth limit!")
			elif len(filelist) >= 128:
				await flash("you have too many files in this directory! (max 128)")
			else:
				foldername = increment_filename("New_Folder", fulldir)
				os.makedirs(f"{fulldir}/{foldername}")
				await flash(f"created new folder {foldername}!")

		elif selections and "DELETE" in form:
			for file in selections:
				if not file or file not in filelist or filelist[file]["type"] == "back":
					selections.remove(file)
					continue
				if filelist[file]["type"] == "folder":
					shutil.rmtree(f"{fulldir}/{file}")
				else:
					os.remove(f"{fulldir}/{file}")
				del filelist[file]
			await log(request, f"{current_user.auth_id} deleted {len(selections)} file(s) ({', '.join(selections)})")
			await flash(f"deleted {len(selections)} file(s) ({', '.join(selections)})")
		
		elif selections and "MOVE" in form:
			folder = form.get("moveto")
			if folder != ".." and (folder not in filelist or filelist[folder]["type"] != "folder"):
				return abort(400)
			movelist = []
			movedir = ff.parent_path(fulldir) if folder == ".." else f"{fulldir}/{folder}"
			folder_filelist = get_filelist(movedir)
			casefold_files = [f.casefold() for f in folder_filelist.keys()]
			for file in selections:
				if not file or file not in filelist or filelist[file]["type"] == "back":
					continue
				if file.casefold() in casefold_files:
					await flash(f"{file} already exists in {folder}!")
					continue
				shutil.move(f"{fulldir}/{file}", f"{movedir}/{file}")
				movelist.append(file)
			await flash(f"moved {len(movelist)} file(s) to {folder} ({', '.join(movelist)})")
		else:
			await flash("no changes made...")

		return redirect(request.url)

	return await render_template("files.html", ff=ff, user=user, folder=folder, filelist=filelist, userdata=userdata, manage=manage)


@app.route("/login", methods=["GET", "POST"])
async def _login():
	if await current_user.is_authenticated:
		return redirect(url_for("_files", user=current_user.auth_id))
	if request.method == "POST":
		form = (await request.form)
		username = form.get("username")
		password = form.get("password")
		remember = True if form.get("rememberme") else False
		if check_password(username, password):
			login_user(AuthUser(username), remember)
			await flash(f"successfully logged in as {username}!")
			return redirect(url_for("_files", user=username))
		else:
			await flash("invalid login!")
	return await render_template("login.html")

@app.route("/logout")
@login_required
async def _logout():
	logout_user()
	await flash("successfully logged out!")
	return redirect("/")

@app.route("/register", methods=["GET", "POST"])
async def _register():
	if request.method == "POST":
		form = (await request.form)
		username = form.get("username")
		password = form.get("password")
		regkey = form.get("key")
		newuserdir = f"{uploads}/{username}"
		if regkey not in [k for kk in cur.execute("SELECT * FROM keys").fetchall() for k in kk]:
			await flash("invalid registration key! ask eli if you need one :3")
		elif user_exists(username):
			await flash("username is already taken!")
		elif not username or not (3 <= len(username) <= 16) or not re.match(abc123_regex, username):
			await flash("invalid username provided! must be between 2 and 16 characters, letters and numbers ONLY!")
		else:
			cur.execute(f"INSERT INTO users (name, pass) VALUES ('{username}', '{hash_password(password)}')")
			cur.execute(f"DELETE FROM keys WHERE key='{regkey}'")
			db.commit()
			os.makedirs(newuserdir)
			login_user(AuthUser(username))
			await log(request, f"{username} created using key {regkey}")
			await flash("account successfully created!")
			return redirect(url_for("_files", user=current_user.auth_id))
	return await render_template("register.html")

@app.route("/forgot", methods=["GET", "POST"])
async def _forgot():
	if await current_user.is_authenticated:
		return redirect(f"/u/{current_user.auth_id}")
	if request.method == "POST":
		global reset_codes
		form = (await request.form)
		username = form.get("username")
		if "REQUEST" in form:
			if user_exists(username):
				reset_codes[username] = generate_key(16)
				await log(request, f"a password reset has been requested for {username}! code: {reset_codes[username]}")
			await flash("a request has been submitted! please get in contact for your code...")

		elif "RESET" in form:
			code = form.get("key")
			new_password = form.get("password")
			if username in reset_codes and code == reset_codes[username]:
				cur.execute(f"UPDATE users SET pass='{hash_password(new_password)}' WHERE name='{username}'")
				db.commit()
				del reset_codes[username]
				await log(request, f"password reset for {username}!")
				await flash("sucessfully reset password! please log in now...")
				return redirect(url_for("_login"))
	return await render_template("forgot.html")


@app.route("/upload", methods=["GET", "POST"])
@login_required
async def _upload():
	user = current_user.auth_id
	folder = request.args.get('folder')
	fulldir = f"{uploads}/{user}" + (f"/{folder}" if folder else "")
	filelist = os.listdir(fulldir) # not using get_filelist(), pointless for this
	userdata = get_userdata(user)

	api = True if "json" in request.args else False # returns json (mainly for sharex)

	if request.method == "POST":
		
		if not os.path.exists(fulldir):
			if api:
				return jsonify({"success": False, "result": "the specified folder does not exist!"}), 404
			return abort(404)

		if len(filelist) >= 128:
			if api:
				return jsonify({"success": False, "result": "you have too many files in this directory! (max 128)"}), 400
			await flash("you have too many files in this directory! (max 128)")
			return redirect(url_for("_files", user=user, folder=folder))

		upload_size = request.content_length
		if not userdata["is_admin"]:
			if upload_size > 1024*1024*96: # 96MB
				if api:
					return jsonify({"success": False, "result": "request too large! 256mb max..."}), 413
				return abort(413)

			if (upload_size + userdata["usage"]) >= userdata["storage"]:
				if api:
					return jsonify({"success": False, "result": "not enough storage left!"}), 413
				await flash("you dont have enough storage to upload this! please make space before trying again...")
				return redirect(url_for("_files", user=user, folder=folder))

		req_files = (await request.files)
		if "upload" not in req_files: # just in case
			return abort(400)

		files = req_files.getlist("upload")
		casefold_files = [f.casefold() for f in filelist]
		upload_list = []
		for file in files:
			if file.filename == "":
				continue
			filename = sanitize_filename(file.filename)
			if filename.casefold() in casefold_files:
				file.close()
				if api:
					return jsonify({"success": False, "result": f"{filename} already exists"}), 400
				await flash(f"{filename} already exists!")
				continue
			upload_list.append(filename)
			await file.save(f"{fulldir}/{filename}")
			await flash(f"sucessfully uploaded {filename}!")
			if api:
				await log(request, f"{user} uploaded a file via api {' '.join(upload_list)}")
				return jsonify({"success": True, "result": f"{filename} successfully uploaded", "location": f"{request.url_root.replace("http://","https://")}/f/{user}{f'/{folder}' if folder else ''}/{filename}"}), 201

		await log(request, f"{user} uploaded {len(upload_list)} file(s) ({' '.join(upload_list)})")
		return redirect(url_for("_files", user=user, folder=folder))

	return await render_template("upload.html")


@app.route("/settings", methods=["GET", "POST"])
@login_required
async def _account():
	userpath = f"{uploads}/{current_user.auth_id}"
	userdata = get_userdata(current_user.auth_id)
	filelist = get_filelist(userpath)

	if request.method == "POST":
		form = (await request.form)

		password_check = False
		if "password" in form and check_password(current_user.auth_id, form["password"]):
			password_check = True
		print(password_check)

		if "CHANGELOGIN" in form:
			login_changed = False
			new_username = form.get("newusername", None)
			new_password = form.get("newpassword", None)
			if not password_check:
				await flash("incorrect password provided!")
				return redirect(request.url)
			if new_username:
				if user_exists(new_username) or not (3 < len(new_username) < 16) or not re.match(abc123_regex, new_username):
					await flash("username is disallowed or already in use! must be between 2 and 16 characters and letters/numbers ONLY!")
					return redirect(request.url)
				cur.execute(f"UPDATE users SET name='{new_username}' WHERE name='{current_user.auth_id}'")
				shutil.move(userpath, f"{uploads}/{new_username}")
				await flash("your username has been updated!")
				await log(request, f"login changed! {current_user.auth_id} -> {new_username}")
				login_changed = True
			if new_password:
				cur.execute(f"UPDATE users SET pass='{hash_password(new_password)}' WHERE name='{current_user.auth_id}'")
				await flash("your password has been updated!")
				login_changed = True
			if login_changed:
				db.commit()
				logout_user()
				await flash("you have been logged out! please enter your new credentials...")
				return redirect("/login")

		elif "DELETEME" in form and form.get("please", "") == "delete my account pretty please":
			if not password_check:
				await flash("incorrect password provided!")
				return redirect(request.url)
			shutil.rmtree(userpath)
			cur.execute(f"DELETE FROM users WHERE name='{current_user.auth_id}'")
			db.commit()
			await log(request, f"{current_user.auth_id} deleted their account")
			await flash("account successfully deleted!")
			logout_user()
			return redirect("/")
	
		else:
			await flash("no changes made...")
	return await render_template("settings.html", filelist=filelist, userdata=userdata)


@app.route("/admin", methods=["GET", "POST"])
@login_required
async def _admin():
	if current_user.auth_id not in user_admins:
		return abort(403)

	keylist = [k for kk in cur.execute("SELECT * FROM keys").fetchall() for k in kk]

	if request.method == "POST":
		form = (await request.form)
		selections = form.getlist("keyselect")

		if "NEWKEY" in form:
			cur.execute(f"INSERT INTO keys (key) VALUES ('{generate_key()}')")
			db.commit()

		elif "DELKEY" in form:
			for key in keylist:
				if key in selections:
					cur.execute(f"DELETE FROM keys WHERE key='{key}'")
			db.commit()

		return redirect(request.url)

	with open(f"{appdir}/log.txt", "r") as log:
		logs = log.readlines()[::-1]
		
	return await render_template("admin.html", dirlist=sorted(os.listdir(uploads)), keylist=keylist, reset_codes=reset_codes, logs=logs)


@app.route("/f/<user>/<path:filepath>")
async def _serve_files(user, filepath):
	fullpath = f"{uploads}/{user}/{filepath}"
	if not os.path.exists(fullpath):
		return abort(404)
	if os.path.isdir(fullpath):
		#TODO: support downloading entire directories
		return abort(404)
	path, file = os.path.split(fullpath)
	return await send_from_directory(path, file)


@app.route('/favicon.ico')
@app.route('/robots.txt')
async def static_from_root():
	return await send_from_directory(app.static_folder, request.path[1:])


@app.errorhandler(400)
@app.errorhandler(401)
@app.errorhandler(403)
@app.errorhandler(404)
@app.errorhandler(413)
@app.errorhandler(500)
async def error_handler(error):
	response = quart.Response(await render_template("error.html", errors={
		400: ["bad request received!",	 "the server could not understand the given request... either you did something wrong or you should try again later!"],
		401: ["login required!",	     "please log in to perform this action!"],
		403: ["access blocked!",		 "you are not authorized to view this page!"],
		404: ["page not found",			 "the page you requested could not be found! if you believe this is in error, please get in contact"],
		413: ["content too large!",		 "the content provided is too large for the server to handle! the max size per upload is 64 MB..."],
		500: ["an error occured!",		 "an error occurred on the servers end! try again, and please get in contact if this persists!",],
	}, error=error,), error.code)
	return response

@app.after_serving
async def shutdown(): # not really necessary but just in case
	db.commit()
	db.close()


hyperconfig = hypercorn.config.Config()
hyperconfig.bind = ["0.0.0.0:42169"]
app.jinja_env.cache = {}

if __name__ == "__main__":
	asyncio.run(hypercorn.asyncio.serve(app, hyperconfig))