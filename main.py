from gui import LoginApp, FileManagerApp

if __name__ == "__main__":
    app = FileManagerApp()
    app.withdraw()

    def on_login_success(password):
        app.deiconify()
        app.set_pw(password)

    login_app = LoginApp(app, on_login_success)
    login_app.grab_set()
    app.mainloop()

