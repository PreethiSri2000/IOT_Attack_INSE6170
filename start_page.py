from kivy.app import App
from kivy.uix.image import Image
from kivy.uix.floatlayout import FloatLayout
from kivy.uix.button import Button
from kivy.uix.screenmanager import Screen, ScreenManager
from show_devices import ShowDevicesScreen
from packet_sniffer import PacketSnifferScreen
from kivy.clock import Clock


class HomeScreen(Screen):
    """Home Screen with a START button."""
    def __init__(self, **kwargs):
        super(HomeScreen, self).__init__(**kwargs)
        layout = FloatLayout()

        # Background image
        background = Image(source="C:\\Users\\preet\\Downloads\\project1.jpg", allow_stretch=True, keep_ratio=False)
        layout.add_widget(background)

        # START button
        start_button = Button(
            text="IoT Scanner",
            font_size=24,
            size_hint=(0.4, 0.1),
            pos_hint={"center_x": 0.5, "center_y": 0.5},
        )
        start_button.bind(on_release=self.start_scan)
        layout.add_widget(start_button)

        self.add_widget(layout)

    def start_scan(self, instance):
        """Navigate to the device list screen."""
        self.manager.transition.direction = "left"
        self.manager.current = "show_devices"



class ScanApp(App):
    """Main IoT Scanner App."""
    def build(self):
        sm = ScreenManager()
        sm.add_widget(HomeScreen(name="home"))
        sm.add_widget(ShowDevicesScreen(name="show_devices"))
        sm.add_widget(PacketSnifferScreen(name="packet_sniffer"))

        return sm


if __name__ == "__main__":
    ScanApp().run()
